import re
import time


# Load Keystream Function

def load_keystream(path):
    print(f"[INFO] Loading keystream from file: {path}")
    with open(path, "r") as f:
        data = f.read()

    # Extract only '0' or '1'
    bits = [int(ch) for ch in re.findall(r"[01]", data)]
    if not bits:
        raise ValueError("[ERROR] No bits (0/1) found in file!")

    print(f"[INFO] Total number of bits read: {len(bits)}")
    preview = "".join(str(b) for b in bits[:60])
    print(f"[INFO] First up to 60 bits of keystream: {preview}")
    print("[INFO] Keystream successfully loaded.\n")
    return bits


# LFSR Sequence Generation + Helper Functions

def int_to_state(x, L):

    return [(x >> (L - 1 - i)) & 1 for i in range(L)] #Converts integer x to an L-bit list [u0, u1, ..., u_{L-1}]


def generate_lfsr_sequence(initial_state, taps, N):
    # taps: list of feed back positions (according to the connection polynomial)
    # N: sequence length
    L = len(initial_state)
    if N <= L:
        return initial_state[:N]

    u = initial_state[:]  # Copy the initial bits

    # Apply recurrence for i >= L
    for i in range(L, N):
        val = 0
        for t in taps:
            val ^= u[i - t]
        u.append(val)
    return u


def hamming_distance(a, b):
    return sum((x ^ y) for x, y in zip(a, b))


def compute_p_star(candidate_seq, z):
    # correlation estimate p* = 1 - d_H(candidate_seq, z) / N
    N = min(len(candidate_seq), len(z))
    d = hamming_distance(candidate_seq[:N], z[:N])
    return 1.0 - d / N



#  Core Correlation Attack for a Single LFSR


def correlation_attack_one_lfsr(z, L, taps, max_states=None, use_prefix=None, lfsr_name=""):

    N_total = len(z)
    if use_prefix is not None:
        N = min(use_prefix, N_total)
    else:
        N = N_total

    max_state_value = 1 << L  # Number of possible states: 2^L
    if max_states is not None:
        max_state_value = min(max_state_value, max_states)

    if not lfsr_name:
        lfsr_name = f"LFSR (L={L})"

    print(f"[INFO] ================================================")
    print(f"[INFO] Starting correlation attack on {lfsr_name}")
    print(f"[INFO] LFSR length L = {L}")
    print(f"[INFO] Feedback taps  = {taps}")
    print(f"[INFO] Search space   = {max_state_value} candidate states (out of 2^{L})")
    print(f"[INFO] Using first N  = {N} keystream bits for correlation.\n")

    best_p_star = -1.0
    best_state_bits = None

    start_time = time.time()

    # Progress print interval
    progress_interval = 1000
    if max_state_value <= 5000:
        progress_interval = 500

    for s in range(max_state_value):
        # Convert integer to L-bit initial state
        init_state = int_to_state(s, L)

        # Generate LFSR sequence for this state
        candidate_seq = generate_lfsr_sequence(init_state, taps, N)

        # Compute correlation estimate
        p_star = compute_p_star(candidate_seq, z[:N])

        if p_star > best_p_star:
            best_p_star = p_star
            best_state_bits = init_state

        # Print periodic progress
        if (s + 1) % progress_interval == 0 or s == max_state_value - 1:
            elapsed = time.time() - start_time
            percent = 100.0 * (s + 1) / max_state_value
            print(
                f"[PROGRESS] {lfsr_name}: "
                f"checked {s+1}/{max_state_value} states "
                f"({percent:.2f}%), elapsed {elapsed:.2f} s, "
                f"current best p* = {best_p_star:.4f}"
            )

    elapsed_total = time.time() - start_time
    print(f"\n[INFO] Finished correlation attack on {lfsr_name}.")
    print(f"[INFO] Total time        : {elapsed_total:.2f} seconds")
    print(f"[INFO] Best p*           : {best_p_star:.6f}")
    print(f"[INFO] Best initial state (bits) : {best_state_bits}")
    print(
        f"[INFO] Best initial state (integer) : "
        f"{int(''.join(str(b) for b in best_state_bits), 2)}\n"
    )

    return best_state_bits, best_p_star


# Main Routine: Recover Key K

def main():
    # Load keystream
    FILE_PATH = "task15.txt"   # Input file containing the provided keystream
    z = load_keystream(FILE_PATH)

    print(f"[INFO] Keystream length N = {len(z)} bits\n")

    # Define LFSR parameters based on the assignment PDF
    # Feedback polynomials:
    # C1(z) = 1 + z^-1 + z^-2 + z^-4 + z^-6 + z^-7 + z^-10 + z^-11 + z^-13
    # C2(z) = 1 + z^-2 + z^-4 + z^-6 + z^-7 + z^-10 + z^-11 + z^-13 + z^-15
    # C3(z) = 1 + z^-2 + z^-4 + z^-5 + z^-8 + z^-10 + z^-13 + z^-16 + z^-17
    LFSR_PARAMS = {
        1: {"L": 13, "taps": [1, 2, 4, 6, 7, 10, 11, 13], "name": "LFSR 1"},
        2: {"L": 15, "taps": [2, 4, 6, 7, 10, 11, 13, 15], "name": "LFSR 2"},
        3: {"L": 17, "taps": [2, 4, 5, 8, 10, 13, 16, 17], "name": "LFSR 3"},
    }

    # Use all keystream bits (193 bits), unless shortened for debugging
    USE_PREFIX = None

    # Perform correlation attack on each LFSR
    recovered_key = {}

    print("[INFO] ================================================")
    print("[INFO] Starting full correlation attack for all 3 LFSRs")
    print("[INFO] ================================================\n")

    for j in [1, 2, 3]:
        params = LFSR_PARAMS[j]
        L = params["L"]
        taps = params["taps"]
        name = params["name"]

        best_state_bits, best_p_star = correlation_attack_one_lfsr(
            z,
            L=L,
            taps=taps,
            max_states=None,     # Set to e.g. 50000 for quick testing
            use_prefix=USE_PREFIX,
            lfsr_name=name
        )

        recovered_key[j] = {
            "state_bits": best_state_bits,
            "p_star": best_p_star
        }

    # Output final recovered key K = (K1, K2, K3)
    print("\n[INFO] =================================================")
    print("[INFO] Final recovered key K = (K1, K2, K3)")
    print("[INFO] =================================================\n")

    for j in [1, 2, 3]:
        state_bits = recovered_key[j]["state_bits"]
        p_star = recovered_key[j]["p_star"]
        state_int = int("".join(str(b) for b in state_bits), 2)

        print(f"[RESULT] {LFSR_PARAMS[j]['name']}:")
        print(f"         Length L           = {LFSR_PARAMS[j]['L']}")
        print(f"         Initial state bits = {state_bits}")
        print(f"         Initial state (int)= {state_int}")
        print(f"         Best p*            = {p_star:.6f}\n")

    print("[INFO] Correlation attack on all three LFSRs completed.")
    print("[INFO] You can now use these initial states as the key K.")


if __name__ == "__main__":
    main()
