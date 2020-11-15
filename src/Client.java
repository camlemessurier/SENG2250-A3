// Client.java
// Author: Cam Le Messurier 3301398
// Implementation of client. 
// Attempts to connect to server and completes simplified SSL handshake and data excahnge

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;

public class Client {

    private String clientID;
    private BigInteger[][] serverRSAkeys;
    private BigInteger rsaSig;
    private String serverID;
    private String sessionID;
    private BigInteger[][] dheKeys;
    private BigInteger sessionKey;
    private Socket socket;

    public Client() {
        clientID = "Client1";
        serverRSAkeys = new BigInteger[2][2];

    }

    public void run() throws UnknownHostException, IOException, NoSuchAlgorithmException, InterruptedException {

        System.out.println("");
        System.out.println("---------------------------------------------------");
        System.out.println("                  Client Started                   ");
        System.out.println("---------------------------------------------------");
        System.out.println("");

        // Connecting to server
        System.out.println("Client: Connecting...");
        boolean connected = false;
        while (!connected) {
            try {
                socket = new Socket("localHost", 6543);
                connected = true;
            } catch (Exception e) {
                System.out.println("Client: Cannot connect to server. Please run server.");
                Thread.sleep(2000);
            }

        }
        // setting up ios
        System.out.println("Client: Connected. \n");
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        System.out.println("Setup Phase");
        System.out.println("------------------------------------------ \n");

        // Sending request
        System.out.println("Client: Sending setup request...");
        out.println("Hello");
        System.out.println("Client: Setup request sent.\n");

        // Receiving public key
        System.out.println("Client: Waiting for RSA Public Key...");
        serverRSAkeys[1][0] = new BigInteger(in.readLine()); // n
        serverRSAkeys[1][1] = new BigInteger(in.readLine()); // d
        System.out.println("Client: RSA Public Key recieved.\n");

        System.out.println("Handshake Phase");
        System.out.println("------------------------------------------ \n");

        // Sending client ID
        System.out.println("Client: Sending client ID...");
        out.println(clientID);
        System.out.println("Client: Client ID sent.\n");

        // Recieving SID and server ID
        System.out.println("Client: Waiting for server ID and session ID...");
        serverID = in.readLine();
        sessionID = in.readLine();
        System.out.println("Client: Server ID and session ID received.\n");

        // Sending DH public key
        System.out.println("Client: Sending DH public key...");
        dheKeys = SSL.dheKeyGen();
        out.println(dheKeys[1][0]);
        System.out.println("Client: DH public key sent.\n");

        // Receiving DH Public Key
        System.out.println("Client: Waiting for DH public key ...");
        dheKeys[1][1] = new BigInteger(in.readLine());
        dheKeys = SSL.dheCalculateSessionKey(dheKeys);
        System.out.println("Client: DH public key recieved. \n");

        // Receiving RSA signature
        System.out.println("Client: Waiting for RSA signature...");
        rsaSig = new BigInteger(in.readLine());
        if (SSL.rsaVerifySig(dheKeys[1][1], rsaSig, serverRSAkeys)) {
            System.out.println("Client: RSA signature verified. \n");
        } else {
            System.out.println("Client: Connection compromised. Exiting...");
            System.exit(1);
        }

        // Calculating session key
        System.out.println("Client: Calculating session key...");
        sessionKey = Utilities.SHA256(dheKeys[0][1].toString());
        System.out.println("Client: Session key derived.");

        // Sending encrypted Finished message
        System.out.println("Client: Sending finished message...");
        out.println(SSL.aesEncrypt("Finished", sessionKey)[0]);
        out.println(SSL.aesEncrypt("Finished", sessionKey)[1]);
        System.out.println("Client: Finished message sent.\n");

        // Recieving encypted Finish message
        System.out.println("Client: Waiting for finished message...");
        String messageIn = SSL.aesDecrypt(in.readLine(), sessionKey);
        String hmac = in.readLine();
        if (messageIn.equals("Finished") && SSL.verifyHMAC(hmac, messageIn, sessionKey)) {
            System.out.println("Client: Session key confirmed.\n");
        } else {
            System.out.println("Client: Session key invalid. Exiting...");
            System.exit(0);
        }

        System.out.println("Data Exchange");
        System.out.println("------------------------------------------ \n");

        // Sending message
        System.out.println("Client: Sending encrypted message...");
        String messageOut = "Hello baby";
        out.println(SSL.aesEncrypt(messageOut, sessionKey)[0]);
        out.println(SSL.aesEncrypt(messageOut, sessionKey)[1]);
        System.out.println("Client: Encrypted message sent.\n");

        // Recieving message
        System.out.println("Client: Receiving encrypted message...");
        messageIn = SSL.aesDecrypt(in.readLine(), sessionKey);
        hmac = in.readLine();

        if (SSL.verifyHMAC(hmac, messageIn, sessionKey)) {
            System.out.println("Client: Message Verified...");
            System.out.println("Message: " + messageIn + "\n");

            System.out.println("Client: Exiting...");
        } else {
            System.out.println("Client: HMAC failed. Exiting...");
        }
        socket.close();
        System.exit(1);
    }
}
