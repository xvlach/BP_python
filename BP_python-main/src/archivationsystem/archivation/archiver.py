import base64
import logging
import ntpath
import os
from contextlib import closing
from hashlib import sha512
from uuid import uuid4

import rfc3161ng
from cryptography.hazmat.primitives.serialization import Encoding

from ..common import utils as common_utils
from ..common.exceptions import FileTransferNotSuccesfullCustomException
from ..database.archived_file import ArchivedFile
from ..database.file_package import FilePackage

logger = logging.getLogger("archivation_system_logging")


class Archiver:
    """
    Archiver class is providing functionality
    for archiving proces of file

    archive function should be called

    on init it needs database library object and
    configuration file. Example could be found
    in example_config and it needs archivation_system_info part
    """

    def __init__(self, db_handler, config: dict):
        self.db_handler = db_handler
        self.archivation_config = config
        self.archived_file_rec = ArchivedFile()
        self.file_pack_record = FilePackage()
        self.archivation_storage_path = self.archivation_config.get(
            "archivation_storage_path"
        )

        "TODO soubory šifrovány pomci AES-256, ostatní informace uloženy v config.php na nextcloudu"

    def archive(self, file_path, owner):
        """
        Method where archiving is called in steps
        it need file path to file which will be archived
        file could be localy or remotly...based on configuration recieved
        on object init

        and it needs original owner name
        """
        logger.debug(
            "executing file archivation with arguments: file_path=%s,"
            " owner=%s",
            str(file_path),
            str(owner),
        )
        self._assign_basic_info(file_path, owner)
        self._validate_certificates()
        self._assign_tsa_info()
        self._transfer_file(file_path)
        self._make_ts0()
        self._make_package0()
        self._sign_package()
        self._make_ts1()
        self._store_used_cert_files()
        self._make_final_package()

        self._insert_db_record()

        return "OK"  # or exception

    def _assign_basic_info(self, file_path, owner):
        logger.info("assigning file name, owner name and original file path")
        self.archived_file_rec.FileName = self._get_file_name(file_path)
        self.archived_file_rec.OwnerName = owner
        self.archived_file_rec.OriginalFilePath = file_path

    def _validate_certificates(self):
        logger.info("validating certificates")
        # path_ca = self.archivation_config["signing_info"]["certificate_path"]
        # path_crl = self.archivation_config["signing_info"]["crl_path"]
        path_tsa_ca_pem = self.archivation_config["TSA_info"]["tsa_ca_pem"]
        self.tsa_current_crl = common_utils.get_current_crl(
            self.archivation_config["TSA_info"]["tsa_crl_url"]
        )
        common_utils.validate_certificate(
            self.tsa_current_crl, path_tsa_ca_pem
        )
        logger.info("TSA cert is valid")
        # with open(  # used for own CRL validation
        #     path_crl, "rb"
        # ) as f:
        #     crl_s = f.load()
        # common_utils.validate_certificate(
        #     crl_s, path_ca
        # )
        # logger.debug("signing cert is valid")

    def _assign_tsa_info(self):
        logger.info("assigning TSA info to file package")
        self.file_pack_record.TimeStampingAuthority = self.archivation_config[
            "TSA_info"
        ]["tsa_tsr_url"]
        cert = common_utils.get_certificate(
            self.archivation_config["TSA_info"]["tsa_cert_path"]
        )
        self.file_pack_record.TsaCert = base64.b64encode(
            cert.public_bytes(Encoding.PEM)
        )

    def _transfer_file(self, file_path):
        if self.archivation_config["remote_access"] is False:
            logger.info("transfering local file to archivation storage")
            (
                self.dst_file_path,
                self.archived_file_rec.PackageStoragePath,
                self.archived_file_rec.OriginFileHashSha512,
            ) = self._transfer_local_file_to_archivation_storage(file_path)
        else:
            logger.info("transfer remote file to archivation storage")
            (
                self.dst_file_path,
                self.archived_file_rec.PackageStoragePath,
                self.archived_file_rec.OriginFileHashSha512,
            ) = self._transfer_remote_file_to_archivation_storage(file_path)

        logger.info("validating data transfer")
        self._validate_data_transfer(
            self.archived_file_rec.OriginFileHashSha512, self.dst_file_path
        )

    def _make_ts0(self):
        logger.info("creating timestamp0")
        ts0 = self._create_timestamp(
            self.archived_file_rec.OriginFileHashSha512, "timestamp0"
        )
        self.archived_file_rec.TimeOfFirstTS = rfc3161ng.get_timestamp(ts0)

    def _make_package0(self):
        logger.info("packing timestamp0 and file to tar package")
        package0_tar_path = self._make_tar_package_from_dir_content(
            self.archived_file_rec.PackageStoragePath, "Package0.tar"
        )
        self.archived_file_rec.Package0HashSha512 = common_utils.get_file_hash(
            sha512, package0_tar_path
        )

    def _sign_package(self):
        logger.info("signing the hash of package0")
        b64signature = self._make_b64signature(
            self.archived_file_rec.Package0HashSha512
        )

        logger.info("storing signature next to package0")
        signature_file_path = common_utils.store_signature(
            self.archived_file_rec.PackageStoragePath, b64signature
        )
        self.archived_file_rec.SignatureHashSha512 = (
            common_utils.get_file_hash(sha512, signature_file_path)
        )

        logger.info("obtaining signing certificate")
        self.archived_file_rec.SigningCert = common_utils.get_certificate(
            self.archivation_config["signing_info"]["certificate_path"]
        ).public_bytes(Encoding.PEM)

    def _make_ts1(self):
        logger.info("creating timestamp1")
        ts1 = self._create_timestamp(
            self.archived_file_rec.SignatureHashSha512, "timestamp1"
        )
        self.file_pack_record.IssuingDate = rfc3161ng.get_timestamp(ts1)
        self.archived_file_rec.ExpirationDateTS = self._get_expiration_date(
            ts1
        )

    def _store_used_cert_files(self):
        logger.info(
            "storing used certificate files and available crls"
            " to archive directory"
        )
        dir_path = common_utils.create_new_dir_in_location(
            self.archived_file_rec.PackageStoragePath, "certificate_files"
        )
        path_ca = self.archivation_config["signing_info"]["certificate_path"]
        # path_crl = self.archivation_config["signing_info"]["crl_path"]
        path_tsa_cert = self.archivation_config["TSA_info"]["tsa_cert_path"]
        path_tsa_ca_pem = self.archivation_config["TSA_info"]["tsa_ca_pem"]

        common_utils.copy_file_to_dir(path_ca, dir_path, "signing_cert.pem")
        # common_utils.copy_file_to_dir(  # used for own CRL validation
        #     path_crl, dir_path, "signing_cert_crl.crl"
        # )
        common_utils.copy_file_to_dir(path_tsa_cert, dir_path, "tsa_cert.crt")
        common_utils.copy_file_to_dir(
            path_tsa_ca_pem, dir_path, "tsa_ca_cert.pem"
        )
        common_utils.store_ts_data(
            self.tsa_current_crl, dir_path, "tsa_cert_crl.crl"
        )

    def _make_final_package(self):
        logger.info("creating final tar package")
        final_tar_path = self._make_tar_package_from_dir_content(
            self.archived_file_rec.PackageStoragePath, "Package1.tar"
        )
        self.file_pack_record.PackageHashSha512 = common_utils.get_file_hash(
            sha512, final_tar_path
        )

    def _insert_db_record(self):
        logger.info("writing results to the database")
        try:
            self.db_handler.add_full_records(
                archf_data=self.archived_file_rec,
                filep_data=self.file_pack_record,
            )
        except Exception as e:
            logger.info(
                "unable to write database record of archivation, deleting"
                " created archived file"
            )
            common_utils.delete_file(self.archived_file_rec.PackageStoragePath)
            raise e

    def _create_timestamp(self, fhash, ts_name):
        logger.debug("obtaining timestamp for file hash %s", str(fhash))
        timestamp = common_utils.get_timestamp(
            self.archivation_config["TSA_info"], fhash
        )
        logger.info(
            "copying %s to %s",
            ts_name,
            self.archived_file_rec.PackageStoragePath,
        )
        common_utils.store_ts_data(
            timestamp, self.archived_file_rec.PackageStoragePath, ts_name
        )
        return timestamp

    def _transfer_local_file_to_archivation_storage(self, file_path):
        logger.debug("getting hash of file: %s", str(file_path))
        origin_hash = common_utils.get_file_hash(sha512, file_path)
        new_dir_path = common_utils.create_new_dir_in_location(
            self.archivation_storage_path, str(uuid4())
        )
        logger.debug(
            "created archivation directory path: %s",
            str(new_dir_path),
        )
        dst_file_path = common_utils.copy_file_to_dir(
            file_path, new_dir_path, self.archived_file_rec.FileName
        )
        logger.debug("file copied, path: %s", str(dst_file_path))
        return dst_file_path, new_dir_path, origin_hash

    def _transfer_remote_file_to_archivation_storage(self, file_path):
        logger.debug("trying to connect to remote storage")
        error_count = 0
        try:
            with closing(
                common_utils.get_sftp_connection(
                    self.archivation_config["remote_access"]
                )
            ) as sftp_connection:
                logger.info("sftp connection created")
                origin_hash = common_utils.get_remote_hash(
                    sftp_connection, file_path, sha512
                )
                copy_dir_path = common_utils.create_new_dir_in_location(
                    self.archivation_storage_path, str(uuid4())
                )
                logger.debug(
                    "created archivation directory path: %s",
                    str(copy_dir_path),
                )

                dst_file_path = self._copy_remote_file_to_archive(
                    sftp_connection, file_path, copy_dir_path
                )
                logger.debug(
                    "remote file copied to destination archive: %s",
                    str(dst_file_path),
                )
        except Exception as e:
            error_count += 1
            if error_count < 5:
                logger.warning(
                    "Exception occured during SFTP transfer, retrying session",
                    exc_info=True,
                )
            else:
                logger.error(
                    "Failed to gather remote file",
                    exc_info=True,
                    stack_info=True,
                )
                raise e
        return dst_file_path, copy_dir_path, origin_hash

    def _get_expiration_date(self, ts):
        years = self.archivation_config["validity_length_in_years"]
        time = rfc3161ng.get_timestamp(ts)
        logger.debug(
            "expiration length of timestamp1 was set to %s",
            str(years),
        )
        return time.replace(year=time.year + years)

    def _get_file_name(self, origin_file_path):
        head, tail = ntpath.split(origin_file_path)
        logger.debug(
            "getting file name from path, splited path head: %s,"
            " tail(should be name) %s ",
            str(head),
            str(tail),
        )
        return tail or ntpath.basename(head)

    def _make_tar_package_from_dir_content(self, dir_path, package_name):
        tar_path = os.path.join(dir_path, package_name)
        logger.debug(
            "creating tar package on path: %s",
            str(tar_path),
        )
        common_utils.create_tar_file_from_dir(dir_path, tar_path)
        return tar_path

    def _make_b64signature(self, hash):
        logger.debug("getting private key")
        pk = common_utils.get_private_key(
            self.archivation_config["signing_info"]["private_key_path"],
            self.archivation_config["signing_info"]["pk_password"],
        )
        logger.debug("signing data")
        return base64.b64encode(common_utils.sign_data(hash, pk))

    def _copy_remote_file_to_archive(
        self, connection_sftp, file_path_to_copy, dst_dir
    ):
        dst = os.path.join(dst_dir, self.archived_file_rec.FileName)
        logger.debug("copying file from sftp storage")
        connection_sftp.get(remotepath=file_path_to_copy, localpath=dst)
        logger.debug("copying finished")
        return dst

    def _validate_data_transfer(self, hash_origin, dst_file_path):
        hash_copy = common_utils.get_file_hash(sha512, dst_file_path)
        logger.debug(
            "hash of origin file: %s \n hash of copy: %s",
            str(hash_origin),
            str(hash_copy),
        )
        if hash_origin != hash_copy:
            logger.error("hashes of original and copied file do not match")
            raise FileTransferNotSuccesfullCustomException(
                "hashes of original and copied file do not match"
            )
        logger.debug("hashes of original and copied file matched")
