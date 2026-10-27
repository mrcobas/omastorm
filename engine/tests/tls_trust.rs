//! Opt-in public TLS qualification of the engine's actual locked reqwest/rustls stack.
//! Never runs in normal offline unit tests and never reads user locations, data or credentials.
use std::time::Duration;

#[test]
#[ignore = "finite public TLS fixture qualification; requires network"]
fn rejects_compromised_emudhra_chains_and_accepts_normal_tls() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let mut fixtures = Vec::new();
        for chain in ["g3b", "g3c", "g3b-aaa", "g3c-aaa"] {
            for kind in ["dv", "ov", "ev"] {
                fixtures.push(format!("{kind}-{chain}-emudhra.we-have-a-problem.com"));
            }
        }
        fixtures.extend([
            "dv-g3b-noct-emudhra.we-have-a-problem.com".into(),
            "dv-g3b-aaa-noct-emudhra.we-have-a-problem.com".into(),
        ]);
        let mut failures = Vec::new();
        for host in &fixtures {
            let result = match client.head(format!("https://{host}/")).send().await {
                Ok(_) => "accepted_tls",
                Err(error) => {
                    let reason = format!("{error:?}");
                    if reason.contains("InvalidCertificate")
                        || reason.contains("certificate verify failed")
                        || reason.contains("CertificateVerification")
                    {
                        "rejected_certificate"
                    } else {
                        "transport_error"
                    }
                }
            };
            println!("{}", serde_json::json!({"host":host,"result":result}));
            if result != "rejected_certificate" {
                failures.push(host.clone());
            }
        }
        for host in ["github.com", "unidata-nexrad-level2.s3.amazonaws.com"] {
            let accepted = client.head(format!("https://{host}/")).send().await.is_ok();
            println!("{}",serde_json::json!({"host":host,"result":if accepted {"accepted_tls"} else {"transport_error"}}));
            if !accepted {
                failures.push(host.into());
            }
        }
        assert!(failures.is_empty(), "Unqualified engine TLS paths: {failures:?}");
    });
}
