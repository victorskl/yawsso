import sys                                                                         # pragma: no cover

if sys.version_info >= (3, 6):                                                     # pragma: no cover
    from yawsso.cli import main                                                    # pragma: no cover
    main()                                                                         # pragma: no cover
else:
    python_version = ".".join(map(str, sys.version_info[:3]))                      # pragma: no cover
    print("This tool requires Python >=3.6. Found {}".format(python_version))      # pragma: no cover
    sys.exit(1)                                                                    # pragma: no cover
