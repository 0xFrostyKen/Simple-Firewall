def read_ip_file(filename):
    try:
        with open(filename, "r") as file:
            return set(line.strip() for line in file if line.strip())
    except FileNotFoundError:
        return set()
