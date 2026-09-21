"""Development entry point for the RSA-without-passphrase example app."""
try:
    from app import app  # pylint: disable=import-error
except ImportError as eImp:
    print(f"The following import ERROR occurred in {__file__}: {eImp}")

if __name__== "__main__":
    try:
        # -----------------Dev mode-----------------
        app.run(host= "127.0.0.1", port= 5000, debug= True)
        # debug= True for apply changes made into the files without restarting the flask server

        # -----------------Prod mode----------------
        # from gevent.pywsgi import WSGIServer
        #appServer= WSGIServer(("127.0.0.1", 5000), app)
        #appServer.serve_forever()
    except Exception as eImp:
        print(f"The following import ERROR occurred in {__file__}: {eImp}")
    finally:
        print("Finishing program")
