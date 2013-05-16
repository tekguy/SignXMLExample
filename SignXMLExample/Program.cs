using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace SignXMLExample
{
    class Program
    {
        static void Main(string[] args)
        {
            #region 1 - Load the XML Document
            var xmlDoc = new XmlDocument();
            xmlDoc.Load(XmlFile);
            #endregion

            #region 2 - Read the certificate file
            var fs = new FileStream(CertificateFile, FileMode.Open);
            var certBytes = new byte[fs.Length];
            fs.Read(certBytes, 0, (Int32)fs.Length);
            fs.Close();
            var cert = new X509Certificate2(certBytes);
            #endregion

            #region 3 - Sign the xml document
            string signedXmlData = GetSignedXml(xmlDoc, cert);
            #endregion

            #region 4 - Validate signed xml against certificate
            bool isValid = Validate(signedXmlData, CertificateFile);
            System.Console.WriteLine("Signed data validated: {0}", isValid);
            #endregion
        }

        public static string CertificateFile { get { return string.Format("{0}\\{1}\\{2}", Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "Data", "certificate.pfx"); } }
        public static string XmlFile { get { return string.Format("{0}\\{1}\\{2}", Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "Data", "sample.xml"); } }
        public static string GetSignedXml(XmlDocument xmlDocument, X509Certificate2 certificate)
        {
            var signedXml = new SignedXml(xmlDocument);
            signedXml.SigningKey = certificate.PrivateKey;
            
            // Add a signing reference, the uri is empty and so the whole document 
            // is signed. 
            var reference = new Reference();
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            reference.Uri = "";
            signedXml.AddReference(reference);

             
            // Add the certificate as key info, because of this the certificate 
            // with the public key will be added in the signature part. 
            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(certificate));
            signedXml.KeyInfo = keyInfo;

            // Generate the signature. 
            signedXml.ComputeSignature();

            // Appends the signature at the end of the xml document. 
            xmlDocument.DocumentElement.AppendChild(signedXml.GetXml());

            // Get XML with Signed node
            return xmlDocument.InnerXml;
        }

        public static bool Validate(string signedXmlData, string certPath)
        {
            bool validSender;
            try
            {
                var assertion = new XmlDocument { PreserveWhitespace = true };
                assertion.LoadXml(signedXmlData);

                // use a namespace manager to avoid the worst of xpaths
                var ns = new XmlNamespaceManager(assertion.NameTable);
                ns.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

                // get the signature XML node
                XmlNode signNode = assertion.SelectSingleNode("/ImportantData/ds:Signature", ns);

                // load the XML signature
                var signedXml = new SignedXml(assertion.DocumentElement);
                signedXml.LoadXml(signNode as XmlElement);

                // check the key and signature match
                var cert = new X509Certificate2(certPath);
                if (!signedXml.CheckSignature(cert, true))
                {
                    throw new SecurityException("Signature check failed.");
                }
                else
                {
                    validSender = true;
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }

            return validSender;
        }
    }
}
