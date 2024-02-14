import com.google.gson.Gson;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class RSAKeyPairGenerator {
    public static void main(String[] args) {
        // Generar un par de claves RSA
        KeyPair keyPair = generateRSAKeyPair();

        // Crear un JSON de ejemplo (en este caso, una "mascota")
        String jsonMascota = "{\"nombre\": \"Firulais\", \"raza\": \"Labrador\"}";

        // Encriptar el JSON con la clave pública
        String jsonEncriptado = encriptar(jsonMascota, keyPair.getPublic());

        // Desencriptar el JSON encriptado con la clave privada
        String jsonDesencriptado = desencriptar(jsonEncriptado, keyPair.getPrivate());

        // Imprimir el JSON original, el JSON encriptado y el JSON desencriptado
        System.out.println("JSON Original: " + jsonMascota);
        System.out.println("JSON Encriptado: " + jsonEncriptado);
        System.out.println("JSON Desencriptado: " + jsonDesencriptado);
    }

    private static KeyPair generateRSAKeyPair() {
        try {
            // Crear un generador de claves RSA
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

            // Inicializar el generador de claves con un tamaño de clave de 2048 bits y un SecureRandom
            SecureRandom secureRandom = new SecureRandom();
            keyPairGenerator.initialize(2048, secureRandom);

            // Generar el par de claves RSA
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String encriptar(String mensaje, PublicKey publicKey) {
        try {
            // Obtener una instancia del cifrador RSA
            Cipher cifrador = Cipher.getInstance("RSA");

            // Inicializar el cifrador en modo de encriptación con la clave pública
            cifrador.init(Cipher.ENCRYPT_MODE, publicKey);

            // Encriptar el mensaje
            byte[] mensajeEncriptado = cifrador.doFinal(mensaje.getBytes());

            // Codificar el mensaje encriptado en Base64 para obtener una representación legible
            return DatatypeConverter.printBase64Binary(mensajeEncriptado);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String desencriptar(String mensajeEncriptado, PrivateKey privateKey) {
        try {
            // Obtener una instancia del cifrador RSA
            Cipher cifrador = Cipher.getInstance("RSA");

            // Inicializar el cifrador en modo de desencriptación con la clave privada
            cifrador.init(Cipher.DECRYPT_MODE, privateKey);

            // Decodificar el mensaje encriptado en Base64
            byte[] mensajeDecodificado = DatatypeConverter.parseBase64Binary(mensajeEncriptado);

            // Desencriptar el mensaje
            byte[] mensajeDesencriptado = cifrador.doFinal(mensajeDecodificado);

            // Convertir el mensaje desencriptado a una cadena
            return new String(mensajeDesencriptado);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }
}
