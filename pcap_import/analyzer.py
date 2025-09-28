from .import_pcap import import_and_process
if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('Usage: analyzer.py file.pcap')
    else:
        import_and_process(sys.argv[1])
