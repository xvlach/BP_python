-- Create tables
use archivationsystem;
CREATE table ArchivedFiles(
	FileID INT auto_increment NOT NULL,
	FileName NVARCHAR(255) NOT NULL,
	OwnerName NVARCHAR(255) NOT NULL,
	OriginalFilePath NVARCHAR(1024) NOT NULL,
	PackageStoragePath NVARCHAR (1024) NOT NULL,
	OriginFileHashSha512 BLOB NOT NULL,
	TimeOfFirstTS DATETIME NOT NULL,
	SigningCert BLOB NOT NULL,
	SignatureHashSha512 BLOB NOT NULL,
	Package0HashSha512 BLOB NOT NULL,
	ExpirationDateTS DATETIME NOT NULL,
	PRIMARY KEY (FileID),
	CONSTRAINT ArchivedFilesUN UNIQUE KEY (FileName, OwnerName)
) ENGINE = InnoDB CHARSET = utf8;
CREATE table FilePackages(
	PackageID INT auto_increment NOT NULL,
	ArchivedFileID INT NOT NULL,
	TimeStampingAuthority NVARCHAR(255) NOT NULL,
	IssuingDate DATETIME NOT NULL,
	TsaCert BLOB NOT NULL,
	PackageHashSha512 BLOB NOT NULL,
	PRIMARY KEY (PackageID),
	CONSTRAINT FilePackagesFK_ArchivedFiles FOREIGN KEY (ArchivedFileID) REFERENCES ArchivedFiles(FileID) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB CHARSET = utf8;