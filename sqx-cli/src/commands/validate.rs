use sqx_core::validator::{DbDialect, PayloadValidator, ValidationResult};
use sqx_core::validator::patterns::matches_known_technique;
use sqx_core::validator::consensus::ConsensusValidator;

pub fn run_validate(payload: String, dialect: String, check_technique: bool) {
    let db_dialect = match dialect.to_lowercase().as_str() {
        "mysql" | "mariadb" => DbDialect::MySQL,
        "postgres" | "postgresql" => DbDialect::Postgres,
        "mssql" | "sqlserver" => DbDialect::MSSQL,
        "sqlite" => DbDialect::SQLite,
        "oracle" => DbDialect::Oracle,
        _ => {
            eprintln!("[-] Unknown dialect: {}. Use: mysql, postgres, mssql, sqlite, oracle", dialect);
            return;
        }
    };
    
    let consensus = ConsensusValidator::new(0.7, 3, 0.9);
    let validator = PayloadValidator::new(consensus, true, true);
    
    println!("[*] Validating payload against {} dialect", dialect);
    println!("[PAYLOAD] {}", payload);
    println!();
    
    let result = validator.validate(&payload, &db_dialect, None);
    
    match result {
        ValidationResult::Valid => {
            println!("[✓] VALID - Payload passed all validation checks");
            
            if check_technique {
                match matches_known_technique(&payload) {
                    Some(technique) => {
                        println!("[✓] Matches known technique: {:?}", technique);
                    }
                    None => {
                        println!("[!] No known SQLi technique pattern matched");
                    }
                }
            }
        }
        ValidationResult::SyntaxError(details) => {
            println!("[✗] INVALID SYNTAX - {}", details);
        }
        ValidationResult::SemanticError(details) => {
            println!("[✗] INVALID SEMANTICS - {}", details);
        }
        ValidationResult::ConsensusFailed(details) => {
            println!("[✗] CONSENSUS FAILED - {}", details);
        }
        ValidationResult::UnknownTechnique(details) => {
            println!("[!] UNKNOWN TECHNIQUE - {}", details);
        }
        ValidationResult::ConstraintViolation(details) => {
            println!("[!] CONSTRAINT VIOLATION - {}", details);
        }
    }
}
