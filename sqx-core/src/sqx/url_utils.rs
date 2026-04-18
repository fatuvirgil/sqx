use crate::sqx::detector::SqliDetector;

impl SqliDetector {
    /// Build test URL with injected payload replacing the target parameter
    pub(crate) fn build_test_url(
        &self,
        url: &str,
        param: &str,
        _original_value: &str,
        payload: &str,
    ) -> String {
        let mut parsed_url = match reqwest::Url::parse(url) {
            Ok(u) => u,
            Err(_) => return url.to_string(),
        };

        let query_pairs: Vec<(String, String)> = parsed_url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        parsed_url.set_query(None);

        let mut param_found = false;
        {
            let mut serializer = parsed_url.query_pairs_mut();
            for (key, value) in query_pairs {
                if key == param {
                    serializer.append_pair(&key, payload);
                    param_found = true;
                } else {
                    serializer.append_pair(&key, &value);
                }
            }
            if !param_found {
                serializer.append_pair(param, payload);
            }
        }

        parsed_url.to_string()
    }
}
