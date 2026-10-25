import random


def miller_rabin(check_num, rounds = 10):
    if check_num < 2:
        return False

    if check_num in (2, 3):
        return True

    if check_num % 2 == 0:
        return False

    b = check_num - 1
    s = (b & -b).bit_length() - 1

    d = b >> s

    for _ in range(rounds):
        rand = random.randrange(2, check_num-1)

        x = power(rand, d, check_num)

        if x == 1 or x == check_num - 1:
            continue

        for r in range(s):
            res = power(rand, (1 << r) * d , check_num)
            if res == check_num - 1:
                break
        else:
            return False

    return True


def power(a, d, n):
    res = 1
    while d > 0:
        if d & 1 == 1:
            res = (res * a) % n
        a = (a * a) % n
        d >>= 1

    return res


def modinv(a, m) -> int:
    a %= m
    old_r, r = a, m
    old_s, s = 1, 0

    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s

    if old_r != 1:
        raise ValueError("Обратный элемент не существует")

    return old_s % m


def hamming_distance_bits(b1: str, b2: str) -> tuple[int, float]:

    n = max(len(b1), len(b2))
    b1 = b1.ljust(n, "0")
    b2 = b2.ljust(n, "0")
    distance = sum(a != b for a, b in zip(b1, b2))
    percent = distance / n * 100 if n else 0.0
    return distance, percent