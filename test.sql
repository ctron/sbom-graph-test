SELECT count(*) FROM EDGES;
SELECT count(*) FROM NODES;

-- examples
--
-- small SBOM with 12 nodes: https://access.redhat.com/security/data/sbom/spdx/DIRSRV-12.1-RHEL-9
-- large SBOM with 79620: https://access.redhat.com/security/data/sbom/spdx/RHOSE-4.15

-- find SBOMs

SELECT a.properties->'name' as name, a.namespace from SBOMS AS a order by name;

-- find one SBOM

SELECT * from SBOMS where namespace = 'https://access.redhat.com/security/data/sbom/spdx/DIRSRV-12.1-RHEL-9';

-- count the nodes of a namespace

SELECT count(*) from NODES where namespace = 'https://access.redhat.com/security/data/sbom/spdx/RHOSE-4.15';

-- count the relationships of a namespace

SELECT
    count(*)
FROM
    nodes AS a
    JOIN edges AS rel on (rel.start_id = a.uid)
WHERE
    a.namespace = 'https://access.redhat.com/security/data/sbom/spdx/RHOSE-4.15'
;

-- find children of one sbom package

SELECT
    a.namespace,
    b.id,
    rel.type,
    a.id
FROM
    nodes AS a
    JOIN edges AS rel ON (a.uid = rel.end_id)
    LEFT JOIN nodes AS b ON (b.uid = rel.start_id)
WHERE
    a.namespace = 'https://access.redhat.com/security/data/sbom/spdx/DIRSRV-12.1-RHEL-9'
AND
    a.id = 'SPDXRef-DOCUMENT';
;

WITH RECURSIVE ctename AS (

    SELECT
        a.uid as a,
        rel.type as rel,
        b.uid as b
    FROM
        sboms AS a
            LEFT JOIN edges AS rel ON (a.uid = rel.end_id)
            LEFT JOIN nodes AS b ON (b.uid = rel.start_id)
    WHERE
        a.namespace = 'https://access.redhat.com/security/data/sbom/spdx/RHOSE-4.15'
      AND
        a.id = 'SPDXRef-DOCUMENT'

    UNION ALL

    SELECT
        a.uid as a,
        rel.type as rel,
        b.uid as b
    FROM
        ctename
            JOIN nodes AS a ON (ctename.b = a.uid)
            LEFT JOIN edges AS rel ON (a.uid = rel.end_id)
            LEFT JOIN nodes AS b ON (b.uid = rel.start_id)
    WHERE
        a.uid = ctename.b
)
SELECT
    a.id,
    a.properties->'name' as a_name,
    a.properties->'purls' as purls,
    a.properties->'cpes' as cpes,
    ctename.rel,
    b.id,
    b.properties->'name' as b_name
FROM
    ctename
        LEFT JOIN nodes AS a ON (ctename.a = a.uid)
        LEFT JOIN nodes AS b ON (ctename.b = b.uid)
-- make it return leaf nodes: WHERE b.id IS NULL
-- make it return non-leaf nodes: WHERE b.id IS NOT NULL
;

-- some purl experiments

CREATE TABLE vulnerabilities (
    ID VARCHAR(64) NOT NULL PRIMARY KEY,
    PURL TEXT
);

DROP TABLE vulnerabilities;

INSERT INTO vulnerabilities (ID, PURL)
VALUES
    ('CVE-1', 'pkg:rpm/redhat/grep@3.6-5.el9?arch=x86_64'),
    ('CVE-2', 'pkg:oci/numaresources-must-gather-rhel9@sha256:58628e92cee18285640370c0f711d5b20452ef0ebd6d99130862fdbcdca54610?repository_url=registry.redhat.io/openshift4/numaresources-must-gather-rhel9&tag=v4.15.1-24')
;

-- select vulnerable packages

SELECT
    *
FROM
    vulnerabilities v
    JOIN packages p ON (p.properties->'purls' ? v.purl )
;
