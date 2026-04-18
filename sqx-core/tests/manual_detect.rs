// Manual test to debug detect_sql_error against sqli-labs
#[tokio::test]
#[ignore = "requires sqli-labs docker container"]
async fn manual_debug_error_based() {
    use sqx_core::sqx::SqliDetector;
    let detector = SqliDetector::new().unwrap();
    let url = "http://localhost:8888/Less-1/?id=%27";
    let resp = detector.send_request(url).await.unwrap();
    println!("STATUS: {}", resp.status);
    println!("BODY LENGTH: {}", resp.body.len());
    println!("BODY SNIPPET: {}", &resp.body[..resp.body.len().min(500)]);
    println!(
        "CONTAINS ERROR: {}",
        resp.body
            .to_lowercase()
            .contains("you have an error in your sql syntax")
    );
}
