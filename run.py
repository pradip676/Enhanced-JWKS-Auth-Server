from server.jwks_server import app

if __name__ == '__main__':
    app.run(port=8080, debug=False)
