using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace CertStoreBrowser
{
    class Program
    {

        /// <summary>
        /// Este método lee el archivo PFX con su correspondiente clave darwin472, firma un texto cualquiera y verifica la firma
        /// de manera asimétrica.
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            try
            {
                string password = "darwin472";
                string certificatePathLocation = "usuario-gqa.pfx";

                // Leemos el certificado desde el PFX (PKCS12 con el certificado público y su clave pública y la clave privada).
                // Este certificado está protegido por password.
                byte[] blob = File.ReadAllBytes(certificatePathLocation);

                X509Certificate2 cert = new X509Certificate2(blob, password, X509KeyStorageFlags.PersistKeySet);

                // Vemos los datos del certificado
                Console.WriteLine(cert);

                // Create a UnicodeEncoder to convert between byte array and string.
                ASCIIEncoding ByteConverter = new ASCIIEncoding();

                string dataString = "Data to Sign";

                // Create byte arrays to hold original, encrypted, and decrypted data. 
                byte[] originalData = ByteConverter.GetBytes(dataString);
                byte[] signedData;

                // Hash and sign the data.
                signedData = HashAndSignBytes(originalData, (RSACryptoServiceProvider)cert.PrivateKey);

                // Vemos cuál es el resultado de lo que firmo.
                Console.WriteLine(Convert.ToBase64String(signedData));

                // Verify the data and display the result to the  
                // console. 
                if (VerifySignedHash(originalData, signedData, (RSACryptoServiceProvider)cert.PublicKey.Key))
                {
                    Console.WriteLine("The data was verified.");
                }
                else
                {
                    Console.WriteLine("The data does not match the signature.");
                }

                // Chequeamos que No coincide cuando le metemos fruta.
                if (VerifySignedHash(originalData, new byte[] { 0x00,0x01,0x02,0x03} , (RSACryptoServiceProvider)cert.PublicKey.Key))
                {
                    Console.WriteLine("The data was verified.");
                }
                else
                {
                    Console.WriteLine("The data does not match the signature (which is OK because it is just a bunch of meaningless bytes");
                }

                Console.ReadLine();

            }
            catch (ArgumentNullException)
            {
                Console.WriteLine("The data was not signed or verified");

            }

            Console.ReadLine();
        }

        

        static void MainReadingCertificates(string[] args)
        {
            try
            {
                // Base64 public x509 certificate.
                String blobString = "MIIFsDCCBJigAwIBAgIKfVUrWAAAAAAAEjANBgkqhkiG9w0BAQUFADBIMRUwEwYKCZImiZPyLGQBGRYFZ2Fkb3IxFjAUBgoJkiaJk/IsZAEZFgZkYXJ3aW4xFzAVBgNVBAMTDmRhcndpbi1HRFJDQTAxMB4XDTEzMDIyMjIwMjcyMloXDTE0MDIyMjIwMjcyMlowgaQxFTATBgoJkiaJk/IsZAEZFgVnYWRvcjEWMBQGCgmSJomT8ixkARkWBmRhcndpbjEPMA0GA1UECxMGREFSV0lOMREwDwYDVQQLEwhFeHRlcm5vczEQMA4GA1UECxMHQmF1ZmVzdDEUMBIGA1UEAxMLVXN1YXJpby1HUUExJzAlBgkqhkiG9w0BCQEWGFVzdWFyaW8tR1FBQGdhZG9yLmNvbS5hcjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA4hQz2abQdCjNoaYLWYIWudI9mDwQZk53uLWGG4KBj9OMAHlqNgIqbb8xaVkml1sMDE+P43if4vC2nRa68qhvPfnigcwo4Pd6iEpxmnb5YLn5Z+rVPT5rAPd0lNOcON2L0Bmm06uy2kBVQNzDtRIZmJQrwXm6iJDUZuP4IUAqYzECAwEAAaOCAsEwggK9MA4GA1UdDwEB/wQEAwIFoDBEBgkqhkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFJB6aiKExnoA1LZtpQBRXeXcEEo1MBcGCSsGAQQBgjcUAgQKHggAVQBzAGUAcjAfBgNVHSMEGDAWgBR9IhR4fVlX6S994Qcpx4alvRJFAzCBzQYDVR0fBIHFMIHCMIG/oIG8oIG5hoG2bGRhcDovLy9DTj1kYXJ3aW4tR0RSQ0EwMSxDTj1nZHJjYTAxLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPWRhcndpbixEQz1nYWRvcj9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgcEGCCsGAQUFBwEBBIG0MIGxMIGuBggrBgEFBQcwAoaBoWxkYXA6Ly8vQ049ZGFyd2luLUdEUkNBMDEsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9ZGFyd2luLERDPWdhZG9yP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MCkGA1UdJQQiMCAGCisGAQQBgjcKAwQGCCsGAQUFBwMEBggrBgEFBQcDAjBNBgNVHREERjBEoCgGCisGAQQBgjcUAgOgGgwYVXN1YXJpby1HUUFAZ2Fkb3IuY29tLmFygRhVc3VhcmlvLUdRQUBnYWRvci5jb20uYXIwDQYJKoZIhvcNAQEFBQADggEBAHUG99x5RF5m10xO1rfsuZr2V3zKPn3hJlDcCKOX84rYv4LZhs3D4q5JnYFOCIEQPDuvpbo1hxhvRkoB19FpJAR9wb5BNUZVs+0iGooOmWfiQlIsP7Y+3llL7RA6xw58uEZKkF+0Ic6NVJAJLXOmjNKcACgn/dgg3fFILVWH5hSRZf8ChvZQYcSZxWmso5Qsb8An/V2EwwOvcS3/nCg/lX7Isbj6WvMPmVB1C/NjH4YpswMJCzFf0I77WJnKmhaxDxwPxK7HruUdP5oj9/m3M3DXiRIIn7GB0Ek39OBn4X1r05ZyPo2T8k+3k6+Y9qPwbQyTu82nVKOyorQvfZItINc=";

                byte[] blob = Convert.FromBase64String(blobString);

                // Use this if you want to save a copy of the certificate.
                //File.WriteAllBytes("retrievedcer.cer", blob);

                X509Certificate2 cert = new X509Certificate2();

                cert.Import(blob);

                Console.WriteLine(cert);


                byte[] Exponent = {1,0,1};

                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();

                //Create a new instance of RSAParameters.
                RSAParameters RSAKeyInfo = new RSAParameters();

                //Set RSAKeyInfo to the public key values. 
                RSAKeyInfo.Modulus = blob;
                RSAKeyInfo.Exponent = Exponent;

                //Import key parameters into RSA.
                RSA.ImportParameters(RSAKeyInfo);



                // Create a UnicodeEncoder to convert between byte array and string.
                ASCIIEncoding ByteConverter = new ASCIIEncoding();

                string dataString = "Data to Sign";

                // Create byte arrays to hold original, encrypted, and decrypted data. 
                byte[] originalData = ByteConverter.GetBytes(dataString);
                byte[] signedData;

                // Create a new instance of the RSACryptoServiceProvider class  
                // and automatically create a new key-pair.
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

                // Export the key information to an RSAParameters object. 
                // You must pass true to export the private key for signing. 
                // However, you do not need to export the private key 
                // for verification.
                RSAParameters Key = RSAalg.ExportParameters(true);


                // HACK
                Key = RSAKeyInfo;

                String xmlKey = RSAalg.ToXmlString(true);

                Console.WriteLine("Key:" + xmlKey);

                // Hash and sign the data.
                signedData = HashAndSignBytes(originalData, Key);

                // Verify the data and display the result to the  
                // console. 
                if (VerifySignedHash(originalData, signedData, Key))
                {
                    Console.WriteLine("The data was verified.");
                }
                else
                {
                    Console.WriteLine("The data does not match the signature.");
                }

                Console.ReadLine();

                RSACryptoServiceProvider RSAalg2 = new RSACryptoServiceProvider();

                RSAalg2.FromXmlString(xmlKey);

                RSAParameters Key2 = RSAalg2.ExportParameters(true);

                // Verify the data and display the result to the  
                // console. 
                if (VerifySignedHash(originalData, signedData, Key2))
                {
                    Console.WriteLine("The data was verified.");
                }
                else
                {
                    Console.WriteLine("The data does not match the signature.");
                }

                Console.ReadLine();

            }
            catch (ArgumentNullException)
            {
                Console.WriteLine("The data was not signed or verified");

            }

            Console.ReadLine();
        }



        static void MainReadingPublicKeys(string[] args)
        {
            try
            {
                String blobString = "MIGJAoGBAOIUM9mm0HQozaGmC1mCFrnSPZg8EGZOd7i1hhuCgY/TjAB5ajYCKm2/MWlZJpdbDAxPj+N4n+Lwtp0WuvKobz354oHMKOD3eohKcZp2+WC5+Wfq1T0+awD3dJTTnDjdi9AZptOrstpAVUDcw7USGZiUK8F5uoiQ1Gbj+CFAKmMxAgMBAAE=";

                //blobString = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3XK9BWuIHIS3R6za4WU/mQ0WlsPD/ErtzSTw2ZmbhI0lyKcQUgk0aRIOaq4vTE+EpRtI6hvhH4AIm+15sWPqxpfuNR0Dvigse+BhuypFsqI+AWiLdj5RrPSzrLcqWgjE5zSjUG4OmxS4NJJRY9UMNaEhtqsrgrFFj4iMX07bz6Joyp85CHpGJhmFjPwU60OlUkGKwvs6TeQXUZlH9ypzXkNAhF4uDchTgEX7A/8yrqHzPx7/r2T0Lww7kp106ACdy9wXTpq5v3tmfNZbZ7K0bEB4g8Ez43Hew1P5b/tabUV4pZL0LkvDCA78ll8FHeuJjZA3+DKlEgyA2EWTs98VTQIDAQAB";

                byte[] blob = Convert.FromBase64String(blobString);


                //File.WriteAllBytes("retrievedcer.cer", blob);

                //cert.Import(blob);

                byte[] Exponent = {1,0,1};

                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();

                //Create a new instance of RSAParameters.
                RSAParameters RSAKeyInfo = new RSAParameters();

                //Set RSAKeyInfo to the public key values. 
                RSAKeyInfo.Modulus = blob;
                RSAKeyInfo.Exponent = Exponent;

                //Import key parameters into RSA.
                RSA.ImportParameters(RSAKeyInfo);



                // Create a UnicodeEncoder to convert between byte array and string.
                ASCIIEncoding ByteConverter = new ASCIIEncoding();

                string dataString = "Data to Sign";

                // Create byte arrays to hold original, encrypted, and decrypted data. 
                byte[] originalData = ByteConverter.GetBytes(dataString);
                byte[] signedData;

                // Create a new instance of the RSACryptoServiceProvider class  
                // and automatically create a new key-pair.
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

                // Export the key information to an RSAParameters object. 
                // You must pass true to export the private key for signing. 
                // However, you do not need to export the private key 
                // for verification.
                RSAParameters Key = RSAalg.ExportParameters(true);


                // HACK
                Key = RSAKeyInfo;

                String xmlKey = RSAalg.ToXmlString(true);

                Console.WriteLine("Key:" + xmlKey);

                // Hash and sign the data.
                signedData = HashAndSignBytes(originalData, Key);

                // Verify the data and display the result to the  
                // console. 
                if (VerifySignedHash(originalData, signedData, Key))
                {
                    Console.WriteLine("The data was verified.");
                }
                else
                {
                    Console.WriteLine("The data does not match the signature.");
                }

                Console.ReadLine();

                RSACryptoServiceProvider RSAalg2 = new RSACryptoServiceProvider();

                RSAalg2.FromXmlString(xmlKey);

                RSAParameters Key2 = RSAalg2.ExportParameters(true);

                // Verify the data and display the result to the  
                // console. 
                if (VerifySignedHash(originalData, signedData, Key2))
                {
                    Console.WriteLine("The data was verified.");
                }
                else
                {
                    Console.WriteLine("The data does not match the signature.");
                }

                Console.ReadLine();

            }
            catch (ArgumentNullException)
            {
                Console.WriteLine("The data was not signed or verified");

            }

            Console.ReadLine();
        }


        public static byte[] HashAndSignBytes(byte[] DataToSign, RSACryptoServiceProvider RSAalg)
        {
            try
            {
                // Hash and sign the data. Pass a new instance of SHA1CryptoServiceProvider 
                // to specify the use of SHA1 for hashing. 
                return RSAalg.SignData(DataToSign, new SHA1CryptoServiceProvider());
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }
        }

        public static byte[] HashAndSignBytes(byte[] DataToSign, RSAParameters Key)
        {
            try
            {
                // Create a new instance of RSACryptoServiceProvider using the  
                // key from RSAParameters.  
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

                RSAalg.ImportParameters(Key);

                // Hash and sign the data. Pass a new instance of SHA1CryptoServiceProvider 
                // to specify the use of SHA1 for hashing. 
                return RSAalg.SignData(DataToSign, new SHA1CryptoServiceProvider());
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }
        }


        public static bool VerifySignedHash(byte[] DataToVerify, byte[] SignedData, RSACryptoServiceProvider RSAalg)
        {
            try
            {
                // Verify the data using the signature.  Pass a new instance of SHA1CryptoServiceProvider 
                // to specify the use of SHA1 for hashing. 
                return RSAalg.VerifyData(DataToVerify, new SHA1CryptoServiceProvider(), SignedData);
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return false;
            }
        }

        public static bool VerifySignedHash(byte[] DataToVerify, byte[] SignedData, RSAParameters Key)
        {
            try
            {
                // Create a new instance of RSACryptoServiceProvider using the  
                // key imported into RSAalg.
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

                RSAalg.ImportParameters(Key);

                // Verify the data using the signature.  Pass a new instance of SHA1CryptoServiceProvider 
                // to specify the use of SHA1 for hashing. 
                return RSAalg.VerifyData(DataToVerify, new SHA1CryptoServiceProvider(), SignedData);

            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return false;
            }
        }

        static void HashSomeStuff(string messageToHash)
        {
            byte[] x_plaintext = Encoding.Default.GetBytes(messageToHash);

            RSACryptoServiceProvider x_rsa = new RSACryptoServiceProvider();

            HashAlgorithm x_sha1 = HashAlgorithm.Create("SHA256");

            byte[] x_rsa_signature = x_rsa.SignData(x_plaintext, x_sha1);

            Console.WriteLine(Convert.ToBase64String(x_rsa_signature));

            Console.ReadLine();
        }
    }

    class pempublic
    {

        // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
        static byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };

        public static void Mainfull(String[] args)
        {
            byte[] x509key;
            byte[] seq = new byte[15];
            int x509size;

            Console.WriteLine("\nEnter PEM-encoded public key file Name: ");
            String filename = Console.ReadLine();
            if (filename == "")  //exit while(true) loop
                return;
            if (!File.Exists(filename))
            {
                Console.WriteLine("File \"{0}\" does not exist!\n", filename);
                return;
            }

            StreamReader sr = File.OpenText(filename);
            String filestr = sr.ReadToEnd();
            sr.Close();

            readKey(filestr);
        }

        public static void readKey(String filestr)
        {
            byte[] x509key;
            int x509size;

            StringBuilder sb = new StringBuilder(filestr);
            sb.Replace("-----BEGIN PUBLIC KEY-----", "");  //remove headers/footers, if present
            sb.Replace("-----END PUBLIC KEY-----", "");

            try
            {        //see if the file is a valid Base64 encoded cert
                x509key = Convert.FromBase64String(sb.ToString());
            }
            catch (System.FormatException)
            {		//if not a b64-encoded publiccert, assume it's binary
                Console.WriteLine("Not a valid  b64 blob; assume binary");
                Stream stream = new FileStream("filename", FileMode.Open);
                int datalen = (int)stream.Length;
                x509key = new byte[datalen];
                stream.Read(x509key, 0, datalen);
                stream.Close();

            }
            x509size = x509key.Length;

            //Console.WriteLine(sb.ToString()) ;
            //PutFileBytes("x509key", x509key, x509key.Length) ;

            // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------

            readKey(x509key);

        }

        public static void readKey(byte[] x509key)
        {
            byte[] seq = new byte[15];
            MemoryStream mem = new MemoryStream(x509key);
            BinaryReader binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading
            byte bt = 0;
            ushort twobytes = 0;

            try
            {

                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130)	//data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();	//advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();	//advance 2 bytes
                else
                    return;

                seq = binr.ReadBytes(15);		//read the Sequence OID
                if (!CompareBytearrays(seq, SeqOID))	//make sure Sequence for OID is correct
                {
                    showBytes("OID:", seq);
                    return;
                }

                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8103)	//data read as little endian order (actual data order for Bit String is 03 81)
                    binr.ReadByte();	//advance 1 byte
                else if (twobytes == 0x8203)
                    binr.ReadInt16();	//advance 2 bytes
                else
                    return;

                bt = binr.ReadByte();
                if (bt != 0x00)		//expect null byte next
                    return;

                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130)	//data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();	//advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();	//advance 2 bytes
                else
                    return;

                twobytes = binr.ReadUInt16();
                byte lowbyte = 0x00;
                byte highbyte = 0x00;

                if (twobytes == 0x8102)	//data read as little endian order (actual data order for Integer is 02 81)
                    lowbyte = binr.ReadByte();	// read next bytes which is bytes in modulus
                else if (twobytes == 0x8202)
                {
                    highbyte = binr.ReadByte();	//advance 2 bytes
                    lowbyte = binr.ReadByte();
                }
                else
                    return;
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };   //reverse byte order since asn.1 key uses big endian order
                int modsize = BitConverter.ToInt32(modint, 0);

                int firstbyte = binr.PeekChar();
                if (firstbyte == 0x00)
                {	//if first byte (highest order) of modulus is zero, don't include it
                    binr.ReadByte();	//skip this null byte
                    modsize -= 1;	//reduce modulus buffer size by 1
                }

                byte[] modulus = binr.ReadBytes(modsize);	//read the modulus bytes

                if (binr.ReadByte() != 0x02)			//expect an Integer for the exponent data
                    return;
                int expbytes = (int)binr.ReadByte();		// should only need one byte for actual exponent data (for all useful values)
                byte[] exponent = binr.ReadBytes(expbytes);


                showBytes("\nExponent", exponent);
                showBytes("\nModulus", modulus);

                // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                RSAParameters RSAKeyInfo = new RSAParameters();
                RSAKeyInfo.Modulus = modulus;
                RSAKeyInfo.Exponent = exponent;
                RSA.ImportParameters(RSAKeyInfo);

                String xmlpublickey = RSA.ToXmlString(false);
                Console.WriteLine("XML encoded RSA public key:\n{0}", xmlpublickey);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }

            finally
            {
                binr.Close();
            }
        }




        private static bool CompareBytearrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            int i = 0;
            foreach (byte c in a)
            {
                if (c != b[i])
                    return false;
                i++;
            }
            return true;
        }



        private static void showBytes(String info, byte[] data)
        {
            Console.WriteLine("{0}  [{1} bytes]", info, data.Length);
            for (int i = 1; i <= data.Length; i++)
            {
                Console.Write("{0:X2}  ", data[i - 1]);
                if (i % 16 == 0)
                    Console.WriteLine();
            }
            Console.WriteLine();
        }


        private static void PutFileBytes(String outfile, byte[] data, int bytes)
        {
            FileStream fs = null;
            if (bytes > data.Length)
            {
                Console.WriteLine("Too many bytes");
                return;
            }
            try
            {
                fs = new FileStream(outfile, FileMode.Create);
                fs.Write(data, 0, bytes);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                fs.Close();
            }
        }

    }

}
