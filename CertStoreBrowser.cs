using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using org.bouncycastle.pkcs;

namespace CertStoreBrowser
{

    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.IO;

    public class CertStoreBrowser
    {
        public static void Traverse()
        {
            //Create new X509 store called teststore from the local certificate store.
            //X509Store store = new X509Store("teststore", StoreLocation.CurrentUser);

            X509Store store = new X509Store();

            store.Open(OpenFlags.ReadWrite);
            X509Certificate2 certificate = new X509Certificate2();

            X509Certificate2Collection storecollection = (X509Certificate2Collection)store.Certificates;
            Console.WriteLine("Store name: {0}", store.Name);
            Console.WriteLine("Store location: {0}", store.Location);
            foreach (X509Certificate2 x509 in storecollection)
            {
                Console.WriteLine("certificate name: {0}", x509.Subject);


                x509.Export(X509ContentType.Pkcs12, "darwin1234");

            }

            //Close the store.
            store.Close();
        }

        public static void Traverses()
        {
            //Create new X509 store called teststore from the local certificate store.
            X509Store store = new X509Store("teststore", StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            X509Certificate2 certificate = new X509Certificate2();

            //Create certificates from certificate files.
            //You must put in a valid path to three certificates in the following constructors.
            X509Certificate2 certificate1 = new X509Certificate2("\\mycerts\\*****.cer");
            X509Certificate2 certificate2 = new X509Certificate2("\\mycerts\\*****.cer");
            X509Certificate2 certificate5 = new X509Certificate2("\\mycerts\\*****.cer");

            //Create a collection and add two of the certificates.
            X509Certificate2Collection collection = new X509Certificate2Collection();
            collection.Add(certificate2);
            collection.Add(certificate5);

            //Add certificates to the store.
            store.Add(certificate1);
            store.AddRange(collection);

            X509Certificate2Collection storecollection = (X509Certificate2Collection)store.Certificates;
            Console.WriteLine("Store name: {0}", store.Name);
            Console.WriteLine("Store location: {0}", store.Location);
            foreach (X509Certificate2 x509 in storecollection)
            {
                Console.WriteLine("certificate name: {0}", x509.Subject);
            }

            //Remove a certificate.
            store.Remove(certificate1);
            X509Certificate2Collection storecollection2 = (X509Certificate2Collection)store.Certificates;
            Console.WriteLine("{1}Store name: {0}", store.Name, Environment.NewLine);
            foreach (X509Certificate2 x509 in storecollection2)
            {
                Console.WriteLine("certificate name: {0}", x509.Subject);
            }

            //Remove a range of certificates.
            store.RemoveRange(collection);
            X509Certificate2Collection storecollection3 = (X509Certificate2Collection)store.Certificates;
            Console.WriteLine("{1}Store name: {0}", store.Name, Environment.NewLine);
            if (storecollection3.Count == 0)
            {
                Console.WriteLine("Store contains no certificates.");
            }
            else
            {
                foreach (X509Certificate2 x509 in storecollection3)
                {
                    Console.WriteLine("certificate name: {0}", x509.Subject);
                }
            }

            //Close the store.
            store.Close();
        }
    }
}
