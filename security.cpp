// Nicholas McCarty
// CSE 381
// Working with key pairs & asymmetrically encrypting messages. 
#include <cstdint>
#include <iostream> 
#include <expected>
#include <iostream>
#include <algorithm> 
#include <cstdlib>
#include <ctime>
#include <vector>
#include <thread>
#include <mutex>

// The output of a public-private key pair generator
struct KeyPair {
    // Random prime numbers
    uint64_t p;
    uint64_t q;

    // Product of random prime numbers
    uint64_t n;

    // Public encryption key
    uint64_t k_e;

    // Private decryption key
    uint64_t k_d;
};

/**
 * Enum representing the status of an operation.
 * 
 * The possible values are:
 * - {@link Status#ok}: Operation completed successfully.
 * - {@link Status#invalid_input}: Invalid input parameters or conditions.
 * - {@link Status#unexpected_condition}: Unexpected condition occurred during the operation.
 * - {@link Status#data_loss_error}: Error indicating potential data loss.
 */
enum class [[nodiscard]] Status {
    ok,
    invalid_input,
    unexpected_condition,
    data_loss_error
};



template <typename T>
using StatusOr = std::expected<T, Status>;

/**
 * @brief Compute base^exponent mod modulus without needing to calculate base^exponent (very large)
 * 
 * @param base The base value.
 * @param exponent The exponent value.
 * @param modulus The modulus value.
 * @return uint64_t The result of base^exponent mod modulus.
 */
uint64_t mod_exp(uint64_t base, uint64_t exponent, uint64_t modulus) {
    uint64_t result = 1;
    base %= modulus;
    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }
        exponent /= 2;
        base = (base * base) % modulus;
    }
    return result;
    // end of scope
}


/**
 * @brief Greatest common divisor
 * 
 * @param a The first number.
 * @param b The second number.
 * @return uint64_t The greatest common divisor of a and b.
 */
uint64_t gcd(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
    // end of scope
}
/**
 * @brief Checks to see if n is a prime number
 * 
 * @param n The number to check for primality.
 * @return true If n is a prime number.
 * @return false If n is not a prime number.
 */
bool isPrime(uint64_t n) {
    if (n <= 1) {
        return false;
    }

    for (uint64_t i = 2; i * i <= n; ++i) {
        if (n % i == 0) {
            return false;
        }
    }
    // end of scope
    return true;
}
/**
 * @brief Generates a random prime number between 1 and n
 * 
 * @param n The upper limit for the random prime number.
 * @return uint64_t A random prime number between 1 and n.
 */
uint64_t generateRandomPrime(uint64_t n) {
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
    uint64_t randomPrime;
    do {
        // Generate a random number between 1 and n
        randomPrime = static_cast<uint64_t>(std::rand() % static_cast<int>(n) + 1);
    } while (!isPrime(randomPrime));

    return randomPrime;
    // end of scope
}

/**
 * @brief Given p, and q, find a number that is relatively prime to (p-1)*(q-1)
 * I.e. the gcd(k_e, (p-1)*(q-1))==1
 * 
 * @param p The first prime number.
 * @param q The second prime number.
 * @return uint64_t A number relatively prime to (p-1)*(q-1).
 */
uint64_t calculatePublicKey(uint64_t p, uint64_t q) {
    uint64_t k_e = 3; // Start with the smallest positive odd integer
    while (gcd(k_e, (p-1)*(q-1)) != 1) {
        k_e += 2; // Increment by 2 to ensure it stays odd
    }

    return k_e;
    // end of scope
}
/**
 * @brief Given p, q, and k_e, calculate the private key which satisfies
 * (k_e*k_d) % ((p-1)(q-1)) == 1
 * 
 * @param p The first prime number.
 * @param q The second prime number.
 * @param k_e The public encryption key.
 * @return uint64_t The private decryption key.
 */
uint64_t calculatePrivateKey(uint64_t p, uint64_t q, uint64_t k_e) {
    uint64_t phiN = (p - 1) * (q - 1);
    for (uint64_t kd = 1; kd < phiN; ++kd) {
        if ((k_e * kd) % phiN == 1) {
            return kd;
        }
    }

    return 0;
    // end of scope
}

/**
 * @brief Generates a random public/private key-pair
 * such that n > message_max.
 * 
 * @param message_max The minimum value for n.
 * @return KeyPair A structure containing the generated key pair.
 */

KeyPair generateKeyPair(int32_t message_max) {
    // TODO 6
    KeyPair ret;

    // Generate the first prime number
    ret.p = generateRandomPrime(static_cast<uint64_t>(message_max));

    // Generate the second prime number, ensuring it is different from the first one
    do {
        ret.q = generateRandomPrime(static_cast<uint64_t>(message_max));
    } while (ret.q == ret.p);

    ret.n = ret.p * ret.q;

    // Setting k_e and k_d variables
    ret.k_e = calculatePublicKey(ret.p, ret.q);
    ret.k_d = calculatePrivateKey(ret.p, ret.q, ret.k_e);
    return ret;

    // end of scope
}
/**
 * @brief Encrypts an integer message using a product and an encryption key.
 * Error if m > n
 * 
 * @param m The integer message to be encrypted.
 * @param n The product of two prime numbers.
 * @param k_e The public encryption key.
 * @return StatusOr<uint64_t> The encrypted message or an error status.
 */
StatusOr<uint64_t> encrypt(uint64_t m, uint64_t n, uint64_t k_e) {
    if (m > n) {
        return std::unexpected(Status::data_loss_error);
    }
    
    // return mod_exp
    return mod_exp(m, k_e, n);

    // end of scope

}
/**
 * @brief Decrypts an integer message given a ciphertext c, N, private decryption key.
 * Error if m > n
 * 
 * @param c The ciphertext to be decrypted.
 * @param n The product of two prime numbers.
 * @param k_d The private decryption key.
 * @return StatusOr<uint64_t> The decrypted message or an error status.
 */
StatusOr<uint64_t> decrypt(uint64_t c, uint64_t n, uint64_t k_d) {
    if (c > n) {
        return std::unexpected(Status::data_loss_error);
    }

   uint64_t decrypted_message = mod_exp(c, k_d, n);
   return decrypted_message;
}

void clientThread(std::mutex &sharedMutex, KeyPair& t0Keys, KeyPair& t1Keys) {
    KeyPair temp = generateKeyPair(255);
    std::unique_lock<std::mutex> lock(sharedMutex);
    std::cout << "clientThread() :: t0 starting" << std::endl;
    (void) temp;
    (void) t0Keys;
    (void) t1Keys;
}

void serverThread(std::mutex &sharedMutex, KeyPair& t0Keys, KeyPair& t1Keys) {
    KeyPair temp = generateKeyPair(255);
    std::unique_lock<std::mutex> lock(sharedMutex);
    std::cout << "serverThread() :: t1 starting" << std::endl;
    (void) t0Keys;
    (void) t1Keys;
    (void) temp;
}


int main() {
    std::mutex sharedMutex;
    KeyPair t0Keys, t1Keys;
    std::thread t0(clientThread, std::ref(sharedMutex), std::ref(t0Keys), std::ref(t1Keys));
    std::thread t1(serverThread, std::ref(sharedMutex), std::ref(t0Keys), std::ref(t1Keys));

    t0.join();
    t1.join();

}

