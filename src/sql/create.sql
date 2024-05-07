CREATE TYPE RELATIONSHIP AS ENUM (
    'Describes',
    'Contains',
    'DependsOn',
    'DevDependsOn',
    'Generates',
    'PackageOf',
    'VariantOf',
    'Other',
    'NotImplemented'
);

CREATE TABLE NODES (
    UID         UUID NOT NULL           PRIMARY KEY,
    ID          VARCHAR(256) NOT NULL,
    NAMESPACE   VARCHAR(256) NOT NULL,

    PROPERTIES JSONB NOT NULL
);

CREATE TABLE SBOMS (
   UID         UUID NOT NULL           PRIMARY KEY
) INHERITS (NODES);

CREATE TABLE PACKAGES (
    UID         UUID NOT NULL           PRIMARY KEY
) INHERITS (NODES);

CREATE TABLE EDGES (
    START_ID   UUID NOT NULL,
    END_ID     UUID NOT NULL,
    TYPE       RELATIONSHIP NOT NULL,

    PROPERTIES JSONB NOT NULL,

    PRIMARY KEY (START_ID, END_ID, TYPE)
);
