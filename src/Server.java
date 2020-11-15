// Server.java
// Author: Cam Le Messurier 3301398
// Implementation of server. 
// Attempts to connect to Client and completes simplified SSL handshake and data excahnge

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;

public class Server {

    private String serverID;
    private BigInteger[][] serverRSAKeys;
    private String messageIn, messageOut;
    private String clientID;
    private BigInteger[][] dheKeys;
    private BigInteger sessionKey;
    private String sessionID;

    public Server() {
        serverID = "SERVER1";
        sessionID = "Session 1";
        serverRSAKeys = SSL.rsaKeyGen();

    }

    public void run() throws NoSuchAlgorithmException {

        System.out.println("");
        System.out.println("---------------------------------------------------");
        System.out.println("                  Server Started                   ");
        System.out.println("---------------------------------------------------");
        System.out.println("");

        System.out.println("Server: Waiting for connection...");
        try {

            ServerSocket serverSocket = new ServerSocket(6543);
            Socket sClientSocket = serverSocket.accept();
            PrintWriter out = new PrintWriter(sClientSocket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(sClientSocket.getInputStream()));

            // Waiting for connection

            messageIn = in.readLine();
            while (!messageIn.equals("Hello")) {
                System.out.println("Waiting for hello");
                messageIn = in.readLine();
            }

            System.out.println("Server: Connected \n");

            // Setup Phase
            System.out.println("Setup Phase");
            System.out.println("------------------------------------------ \n");

            // Sending publis RSA keys
            System.out.println("Server: Sending Public RSA Keys...");
            out.println(serverRSAKeys[1][0]);
            out.println(serverRSAKeys[1][1]);
            System.out.println("Server: RSA Public Keys sent.\n");

            // Handshake Phase
            System.out.println("Handshake Phase");
            System.out.println("------------------------------------------ \n");

            // Waiting for client ID
            System.out.println("Server: Waiting for client ID...");
            clientID = in.readLine();
            System.out.println("Server: Client ID recieved.\n");

            // Sending session ID and server ID
            System.out.println("Server: Sending Session ID and Server ID...");
            out.println(sessionID);
            out.println(serverID);
            System.out.println("Server: RSA Public Keys sent.\n");

            System.out.println("Server: Sending DHE Public Keys...");
            dheKeys = SSL.dheKeyGen();
            out.println(dheKeys[1][0]);
            System.out.println("Server: DHE Public Keys sent. \n");

            System.out.println("Server: Waiting for DHE Public Keys...");
            dheKeys[1][1] = new BigInteger(in.readLine());
            dheKeys = SSL.dheCalculateSessionKey(dheKeys);
            System.out.println("Server: DHE Public Keys received.\n");

            System.out.println("Server: Sending RSA signature...");
            out.println(SSL.rsaSigGen(dheKeys[1][0], serverRSAKeys));
            System.out.println("Server: RSA signature sent.\n");

            System.out.println("Server: Calculating session key...");
            sessionKey = Utilities.SHA256(dheKeys[0][1].toString());
            System.out.println("Server: Session key derived.\n");

            // Recieving encypted Finish message

            System.out.println("Server: Waiting for finish message...");
            String messageIn = SSL.aesDecrypt(in.readLine(), sessionKey);
            String hmac = in.readLine();
            if (messageIn.equals("Finished") && SSL.verifyHMAC(hmac, messageIn, sessionKey)) {
                System.out.println("Server: Session key confirmed.\n");
            } else {
                System.out.println("Server: Session key invalid. Exiting...\n");
                System.exit(0);
            }

            System.out.println("Server: Sending Finish message...");
            out.println(SSL.aesEncrypt("Finished", sessionKey)[0]);
            out.println(SSL.aesEncrypt("Finished", sessionKey)[1]);
            System.out.println("Server: Finish message sent.\n");

            System.out.println("Data Exchange");
            System.out.println("------------------------------------------ \n");

            System.out.println("Server: Receiving encrypted message...");
            messageIn = SSL.aesDecrypt(in.readLine(), sessionKey);
            hmac = in.readLine();
            if (SSL.verifyHMAC(hmac, messageIn, sessionKey)) {
                System.out.println("Server: Message Verified...");
                System.out.println("Message: " + messageIn + "\n");

            } else {
                System.out.println("Server: HMAC failed. Exiting...");
            }

            // Sending message
            System.out.println("Server: Sending encrypted message...");
            String messageOut = "What doing";
            out.println(SSL.aesEncrypt(messageOut, sessionKey)[0]);
            out.println(SSL.aesEncrypt(messageOut, sessionKey)[1]);
            System.out.println("Server: Encrypted message sent. \n");
            System.out.println("Server: Exiting...");
            serverSocket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
