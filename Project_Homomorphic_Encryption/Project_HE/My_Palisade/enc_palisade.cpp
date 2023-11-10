#include "palisade.h"
#include <iostream>

using namespace lbcrypto;

int main() {
  std::vector<int64_t> vectorOfInts1, vectorOfInts2; 
  int n, i=0, e;
  clock_t start, end;
  // Step 1: Set CryptoContext

  // Set the main parameters
  int plaintextModulus = 65537;
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic;
  uint32_t depth = 2;

  // Instantiate the crypto context
  CryptoContext<DCRTPoly> cryptoContext =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          plaintextModulus, securityLevel, sigma, 0, depth, 0, OPTIMIZED);

  // Enable features that you wish to use
  cryptoContext->Enable(ENCRYPTION);
  cryptoContext->Enable(SHE);

  // Step 2: Key Generation

  // Initialize Public Key Containers
  LPKeyPair<DCRTPoly> keyPair;

  // Generate a public/private key pair
  keyPair = cryptoContext->KeyGen();

  // Generate the relinearization key
  cryptoContext->EvalMultKeyGen(keyPair.secretKey);

  // Generate the rotation evaluation keys
  cryptoContext->EvalAtIndexKeyGen(keyPair.secretKey, {1, 2, -1, -2});                 

  i=0;       
    std::cout << "Quanti elementi vuoi inserire nel primo vettore? " << std::endl;
  std::cin >> n;
  while(i<n) {
  std::cout << "Inserisci elemento: ";
  std::cin >> e;
  vectorOfInts1.insert(vectorOfInts1.begin()+i, e);
  i++;
  }
  
  i=0;
  std::cout << "Quanti elementi vuoi inserire nel secondo vettore? " << std::endl;
  std::cin >> n;
  while(i<n) {
  std::cout << "Inserisci elemento: ";
  std::cin >> e;
  vectorOfInts2.insert(vectorOfInts2.begin()+i, e);
  i++;
  }   
 
  // Sample Program: Step 3: Encryption

  Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);
  
  Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

  // The encoded vectors are encrypted
  auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
  auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

  // Step 4: Evaluation
  start = clock();
  // Homomorphic additions
  auto ciphertextAddResult = cryptoContext->EvalAdd(ciphertext1, ciphertext2);
  // Homomorphic multiplications
  auto ciphertextMultResult = cryptoContext->EvalMult(ciphertext1, ciphertext2);

  // Step 5: Decryption

  // Decrypt the result of additions
  Plaintext plaintextAddResult;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddResult,
                         &plaintextAddResult);

  // Decrypt the result of multiplications
  Plaintext plaintextMultResult;
  cryptoContext->Decrypt(keyPair.secretKey, ciphertextMultResult,
                         &plaintextMultResult);

  end = clock();

  std::cout << "Plaintext #1: " << plaintext1 << std::endl;
  std::cout << "Plaintext #2: " << plaintext2 << std::endl;


  // Output results
  std::cout << "\nResults of homomorphic computations" << std::endl;
  std::cout << "#1 + #2: " << plaintextAddResult << std::endl;
  std::cout << "#1 * #2: " << plaintextMultResult << std::endl;
  std::cout << "\nTempo totale operazioni di addizione e moltiplicazione = " <<(double)(end-start)/CLOCKS_PER_SEC << " s " << std::endl;


  return 0;
}
