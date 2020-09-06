from HashTab import HashTab
from Shell import Shell
import time


def test():
    size = 1000
    missing = 0
    found = 0

    # create a hash table with an initially small number of bukets
    c = HashTab(100)

    # Now insert size key/data pairs, where the key is a string consisting
    # of the concatenation of "foobarbaz" and i, and the data is i
    inserted = 0
    for i in range(size):
        if c.insert(str(i) + "foobarbaz", i):
            inserted += 1
    print("There were", inserted, "nodes successfully inserted")

    # Make sure that all key data pairs that we inserted can be found in the
    # hash table. This ensures that resizing the number of buckets didn't
    # cause some key/data pairs to be lost.
    for i in range(size):
        ans = c.find(str(i) + "foobarbaz")
        if ans is None or ans != i:
            print(i, "Couldn't find key", str(i) + "foobarbaz")
            missing += 1

    print("There were", missing, "records missing from Cuckoo")

    # Makes sure that all key data pairs were successfully deleted
    for i in range(size):
        c.delete(str(i) + "foobarbaz")

    for i in range(size):
        ans = c.find(str(i) + "foobarbaz")
        if ans != None or ans == i:
            print(i, "Couldn't delete key", str(i) + "foobarbaz")
            found += 1
    print("There were", found, "records not deleted from Cuckoo")


def __main():
    print("Starting the code")
    shell = Shell()
    shell.execute("echo \"1234\" |  sudo -S timout 100 tcpdump -w output.pcap")
    print("Please check the pcap file")
    print("------------------------------------------")

    # test()


if __name__ == '__main__':
    __main()
