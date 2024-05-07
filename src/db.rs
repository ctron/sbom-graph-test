use crate::rel::Relationship;
use anyhow::Context;
use serde_json::json;
use spdx_rs::models::SPDX;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use tokio_postgres::types::Json;
use tokio_postgres::{connect, Client, NoTls};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Key {
    pub id: String,
    pub namespace: String,
}

impl Display for Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} / {}", self.namespace, self.id)
    }
}

const NAMESPACE: Uuid = Uuid::from_bytes([
    0xc7, 0x09, 0x1b, 0x73, 0x48, 0xed, 0x46, 0xcc, 0xb0, 0x5d, 0x08, 0x8a, 0x23, 0xc7, 0x99, 0x13,
]);

impl Key {
    pub fn to_uuid(&self) -> Uuid {
        Uuid::new_v5(
            &Uuid::new_v5(&NAMESPACE, self.namespace.as_bytes()),
            self.id.as_bytes(),
        )
    }
}

pub struct Database {
    client: Client,
}

impl Deref for Database {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl Database {
    pub async fn new(config: &str) -> anyhow::Result<Self> {
        let (client, connection) = connect(config, NoTls).await?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {}", e);
            }
        });

        // init database

        client.batch_execute(include_str!("sql/drop.sql")).await?;
        client.batch_execute(include_str!("sql/create.sql")).await?;

        // done

        Ok(Self { client })
    }

    pub async fn ingest(&mut self, sbom: SPDX) -> anyhow::Result<()> {
        let tx = self.client.transaction().await?;

        log::info!(
            "Ingest - packages: {}, relationships: {}",
            sbom.package_information.len(),
            sbom.relationships.len()
        );

        let namespace = sbom
            .document_creation_information
            .spdx_document_namespace
            .clone();

        // insert SBOM

        let key = Key {
            id: sbom.document_creation_information.spdx_identifier.clone(),
            namespace: namespace.clone(),
        };

        let num = tx
            .execute(
                r#"
INSERT INTO SBOMS (
    UID,
    ID,
    NAMESPACE,
    PROPERTIES
) VALUES (
    $1, $2, $3, $4
)
ON CONFLICT DO NOTHING
        "#,
                &[
                    &key.to_uuid(),
                    &sbom.document_creation_information.spdx_identifier,
                    &namespace,
                    &Json(json!({
                        "name": &sbom.document_creation_information.document_name,
                    })),
                ],
            )
            .await
            .with_context(|| format!("inserting SBOM: {key:?}"))?;

        if num == 0 {
            log::warn!("Duplicate SBOM: {key:?}");
            return Ok(());
        }

        let stmt = tx
            .prepare(
                r#"
INSERT INTO PACKAGES (
    UID,
    ID,
    NAMESPACE,
    PROPERTIES
) VALUES (
    $1, $2, $3, $4
)
ON CONFLICT DO NOTHING
"#,
            )
            .await?;

        for package in &sbom.package_information {
            let key = Key {
                id: package.package_spdx_identifier.clone(),
                namespace: namespace.clone(),
            };

            let cpes: Vec<_> = package
                .external_reference
                .iter()
                .filter(|p| p.reference_type == "cpe22Type")
                .map(|p| &p.reference_locator)
                .collect();

            let purls: Vec<_> = package
                .external_reference
                .iter()
                .filter(|p| p.reference_type == "purl")
                .map(|p| &p.reference_locator)
                .collect();

            tx.execute(
                &stmt,
                &[
                    &key.to_uuid(),
                    &key.id,
                    &key.namespace,
                    &Json(json!({
                        "name": package.package_name,
                        "purls": purls,
                        "cpes": cpes,
                    })),
                ],
            )
            .await
            .with_context(|| format!("inserting package: {key:?}"))?;
        }

        // relationships

        let stmt = tx
            .prepare(
                r#"
INSERT INTO EDGES (
    START_ID,
    END_ID,
    TYPE,
    PROPERTIES
) VALUES (
    $1, $2, $3, $4
)
ON CONFLICT DO NOTHING
;
"#,
            )
            .await?;
        for rel in &sbom.relationships {
            let (a, r#type, b) = Relationship::from_rel(
                rel.spdx_element_id.clone(),
                &rel.relationship_type,
                rel.related_spdx_element.clone(),
            );
            let a = Key {
                id: a,
                namespace: namespace.clone(),
            };
            let b = Key {
                id: b,
                namespace: namespace.clone(),
            };

            let num = tx
                .execute(
                    &stmt,
                    &[&a.to_uuid(), &b.to_uuid(), &r#type, &Json(json!({}))],
                )
                .await?;

            if num == 0 {
                log::warn!("Duplicate package relation: {a} -[{type}]-> {b}");
            }
        }

        // commit

        tx.commit().await?;

        // done

        Ok(())
    }
}
