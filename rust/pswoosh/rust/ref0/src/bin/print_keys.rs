use ref0::*;
use std::thread;
use ref0::sysA::*;

const STACK_SIZE: usize = 100 * 1024 * 1024;

// Increase stack size for the tests
fn run_test_with_stack<F>(test_fn: F, test_name: &str) 
where 
    F: FnOnce() + Send + 'static 
{
    let builder = thread::Builder::new().stack_size(STACK_SIZE); // 100 MB stack size
    let test_name = String::from(test_name);
    let handler = builder.spawn(move || {
        println!("Running {} with 16MB stack", test_name);
        test_fn();
    }).unwrap();
    
    handler.join().unwrap();
}

#[test]
fn test_keys(){
    run_test_with_stack(|| {
        // Step 1: Generate key pairs
        let (sk1, pk1) = pswoosh_keygen(&A, true);
        let (sk2, pk2) = pswoosh_keygen(&At, false);
        // Step 3: Exchange public keys (happens in a real application)
        
        // Step 4: Derive the shared secret
        let ss1 = pswoosh_skey_deriv(&pk1, &pk2, &sk1, true);
        let ss2 = pswoosh_skey_deriv(&pk2, &pk1, &sk2, false);
        
        // Verify that both parties derived the same secret
        assert_eq!(ss1, ss2, "ERROR: shared secrets don't match!");
        
        // Use the shared secret for encryption or other purposes
        println!("Successfully generated shared secret!");
        println!("Shared secret: {:?}", ss1);
        println!("Shared secret 2: {:?}", ss2);
    }, "test_keys");
}

#[test]
fn test_keys_random_matrix(){

    run_test_with_stack(|| {
        let mut seed: [u8; SYMBYTES] = [0; SYMBYTES];
        getrandom::getrandom(&mut seed).expect("getrandom failed");
        let a = genmatrix(&seed, true);   // Matrix A
        let at = genmatrix(&seed, false);   // Initialize matrix At
        
        // Step 1: Generate key pairs
        let (sk1, pk1) = pswoosh_keygen(&a, true);
        let (sk2, pk2) = pswoosh_keygen(&at, true);
        // Step 3: Exchange public keys (happens in a real application)
        
        // Step 4: Derive the shared secret
        let ss1 = pswoosh_skey_deriv(&pk1, &pk2, &sk1, true);
        let ss2 = pswoosh_skey_deriv(&pk2, &pk1, &sk2, false);
        
        // Verify that both parties derived the same secret
        assert_eq!(ss1, ss2, "ERROR: shared secrets don't match!");
        
        // Use the shared secret for encryption or other purposes
        println!("Successfully generated shared secret!");
        println!("Shared secret: {:?}", ss1);
        println!("Shared secret 2: {:?}", ss2);
    }, "test_keys_random_matrix");
}
