using System;
using System.IO;
using System.Xml;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Cryptography;

namespace kobackupdec
{
    /// <summary>
    /// HUAWEI KoBackup decryptor in C#
    /// </summary>
    public static class kobackupdec
    {
        #region Parser routines for 'info.xml'

        static object xml_get_column_value(XmlNode xml_node)
        {
            XmlNode child = xml_node.FirstChild;
            if (child.Name != "value")
            {
                Console.WriteLine("xml_get_column_value: entry has no values!");
                return null;
            }

            if (child.Attributes["Null"] != null)
                return null;
            if (child.Attributes["String"] != null)
                return child.Attributes["String"].Value;
            if (child.Attributes["Integer"] != null)
                return Convert.ToInt32(child.Attributes["Integer"].Value);

            Console.WriteLine("xml_get_column_value: unknown value attribute.");
            return null;
        }

        static void parse_backup_files_type_info(ref Decryptor decryptor, XmlDocument xml_entry)
        {
            XmlNodeList elemList = xml_entry.GetElementsByTagName("column");
            foreach (XmlNode entry in elemList)
            {
                string name = entry.Attributes["name"].Value;
                if (name == "e_perbackupkey")
                    decryptor.e_perbackupkey = xml_get_column_value(entry) as string;
                else if (name == "pwkey_salt")
                    decryptor.pwkey_salt = xml_get_column_value(entry) as string;
                else if (name == "type_attch")
                    decryptor.type_attch = Convert.ToInt32(xml_get_column_value(entry));
                else if (name == "checkMsg")
                    decryptor.checkMsg = xml_get_column_value(entry) as string;
            }
        }

        static void ignore_entry(XmlNode xml_entry)
        {
            string aString = xml_entry.Attributes["table"].Value;
            Console.WriteLine("ignoring entry: " + aString);
        }

        static DecryptMaterial parse_backup_file_module_info(XmlDocument xml_entry)
        {
            string aString = xml_entry.FirstChild.Attributes["table"].Value;
            DecryptMaterial decm = new DecryptMaterial(aString);

            XmlNodeList elemList = xml_entry.GetElementsByTagName("column");
            foreach (XmlNode entry in elemList)
            {
                string name = entry.Attributes["name"].Value;
                if (name == "encMsgV3")
                    decm.encMsgV3 = xml_get_column_value(entry) as string;
                else if (name == "checkMsgV3")
                {
                    // TBR: reverse this double sized checkMsgV3.
                }
                else if (name == "name")
                    decm.name = xml_get_column_value(entry) as string;
            }

            if (decm.do_check() == false)
                return null;

            return decm;
        }

        static HybridDictionary parse_info_xml(string filepath, ref Decryptor decryptor, HybridDictionary decrypt_material_dict)
        {
            // Create the XmlDocument.
            XmlDocument info_dom = new XmlDocument();
            info_dom.Load(filepath);

            if (info_dom.GetElementsByTagName("info.xml").Count != 1)
            {
                Console.WriteLine("First tag should be 'info.xml', not '{0}'", info_dom.FirstChild.Name);
                decryptor = null;
                return null;
            }

            string parent = Directory.GetParent(filepath).FullName;

            XmlDocument doc;
            XmlNodeList elemList = info_dom.GetElementsByTagName("row");
            foreach (XmlNode entry in elemList)
            {
                string title = entry.Attributes["table"].Value;
                switch (title)
                {
                    case "BackupFilesTypeInfo":
                        doc = new XmlDocument();
                        doc.LoadXml(entry.OuterXml);
                        parse_backup_files_type_info(ref decryptor, doc);
                        break;
                    case "HeaderInfo":
                    case "BackupFilePhoneInfo":
                    case "BackupFileVersionInfo":
                        ignore_entry(entry);
                        break;
                    case "BackupFileModuleInfo":
                    case "BackupFileModuleInfo_Contact":
                    case "BackupFileModuleInfo_Media":
                    case "BackupFileModuleInfo_SystemData":
                        doc = new XmlDocument();
                        doc.LoadXml(entry.OuterXml);
                        DecryptMaterial dec_material = parse_backup_file_module_info(doc);
                        if (dec_material != null)
                        {
                            string dkey = Path.Combine(parent, dec_material.name);
                            decrypt_material_dict[dkey] = dec_material;
                        }
                        break;
                    default:
                        Console.WriteLine("Unknown entry in 'info.xml': {0}", title);
                        break;
                }
            }

            return decrypt_material_dict;
        }

        static HybridDictionary parse_xml(string filepath, HybridDictionary decrypt_material_dict)
        {
            string filename = Path.GetFileName(filepath);
            Console.WriteLine("parsing xml file " + filename);

            // Create the XmlDocument.
            XmlDocument xml_dom = new XmlDocument();
            xml_dom.Load(filepath);

            string fullpath = Directory.GetParent(filepath).FullName;
            string parent = Path.Combine(fullpath, Path.GetFileNameWithoutExtension(filepath));

            XmlNodeList elemList = xml_dom.GetElementsByTagName("File");
            foreach (XmlNode node in elemList)
            {
                string path = node.SelectSingleNode("Path").InnerText;
                string iv = node.SelectSingleNode("Iv").InnerText;
                if (!String.IsNullOrEmpty(path) && !String.IsNullOrEmpty(iv))
                {
                    DecryptMaterial dec_material = new DecryptMaterial(Path.GetFileNameWithoutExtension(filepath));
                    // XML files use Windows style path separator, backslash.
                    dec_material.path = path;
                    dec_material.iv = iv;
                    string dkey = Path.Combine(parent, path.TrimStart(new char[] { '\\' }));
                    decrypt_material_dict[dkey] = dec_material;
                }
            }

            return decrypt_material_dict;
        }

        #endregion

        #region Some useful functions

        /// <summary>
        /// Extract TAR archive to directory.
        /// </summary>
        /// <param name="inputStream">The input Stream representing the TAR archive.</param>
        /// <param name="outputDir">The output directory.</param>
        /// <seealso cref="https://stackoverflow.com/questions/8863875/decompress-tar-files-using-c-sharp"/>
        static void TAR_Extract(Stream inputStream, string outputDir)
        {
            var buffer = new byte[100];
            while (true)
            {
                inputStream.Read(buffer, 0, 100);
                var name = Encoding.ASCII.GetString(buffer).Trim('\0', ' ');
                if (String.IsNullOrWhiteSpace(name))
                    break;
                inputStream.Seek(24, SeekOrigin.Current);
                inputStream.Read(buffer, 0, 12);

                long size;
                string hex = Encoding.ASCII.GetString(buffer, 0, 12).Trim('\0', ' ');
                try
                {
                    size = Convert.ToInt64(hex, 8);
                }
                catch (Exception ex)
                {
                    throw new Exception("Could not parse hex: " + hex, ex);
                }

                inputStream.Seek(376L, SeekOrigin.Current);

                var output = Path.Combine(outputDir, name);
                if (size > 0) // ignores directory entries
                {
                    if (!Directory.Exists(Path.GetDirectoryName(output)))
                        Directory.CreateDirectory(Path.GetDirectoryName(output));
                    using (var str = File.Open(output, FileMode.OpenOrCreate, FileAccess.Write))
                    {
                        var buf = new byte[size];
                        inputStream.Read(buf, 0, buf.Length);
                        str.Write(buf, 0, buf.Length);
                    }
                }

                var pos = inputStream.Position;

                var offset = 512 - (pos % 512);
                if (offset == 512)
                    offset = 0;

                inputStream.Seek(offset, SeekOrigin.Current);
            }
        }

        /// <summary>
        /// Used to get the longest common sub-path in a list of paths.
        /// </summary>
        /// <param name="Paths">A list of paths.</param>
        /// <returns>Returns a string which represents the longest common sub-path in the specified list.</returns>
        /// <seealso cref="https://www.rosettacode.org/wiki/Find_common_directory_path"/>
        static string FindCommonPath(IEnumerable<string> Paths)
        {
            string Separator = @"\";

            string CommonPath = String.Empty;
            List<string> SeparatedPath = Paths
                .First(str => str.Length == Paths.Max(st2 => st2.Length))
                .Split(new string[] { Separator }, StringSplitOptions.RemoveEmptyEntries)
                .ToList();

            foreach (string PathSegment in SeparatedPath.AsEnumerable())
            {
                if (CommonPath.Length == 0 && Paths.All(str => str.StartsWith(PathSegment)))
                {
                    CommonPath = PathSegment;
                }
                else if (Paths.All(str => str.StartsWith(CommonPath + Separator + PathSegment)))
                {
                    CommonPath += Separator + PathSegment;
                }
                else
                {
                    break;
                }
            }

            return CommonPath;
        }

        #endregion

        internal static void decrypt(string user_password, string backup_path_in, string dest_path_out)
        {
            Console.WriteLine("getting files and folders from: " + backup_path_in);
            if (!Directory.Exists(backup_path_in))
            {
                Console.WriteLine("input backup folder does not exist!");
                return;
            }

            Console.WriteLine("using output folder: " + dest_path_out);
            if (Directory.Exists(dest_path_out))
            {
                List<string> files = Directory.GetFiles(dest_path_out, "*.*", SearchOption.AllDirectories).ToList();
                if (files.Count > 0)
                {
                    Console.WriteLine("output folder contains {0} files, cannot overwrite them!", files.Count);
                    return;
                }
            }

            List<string> backup_all_files = Directory.GetFiles(backup_path_in, "*.*", SearchOption.AllDirectories).ToList();
            List<string> xml_files = new List<string>();
            List<string> apk_files = new List<string>();
            List<string> tar_files = new List<string>();
            List<string> db_files = new List<string>();
            List<string> enc_files = new List<string>();
            List<string> unk_files = new List<string>();
            List<string> done_list;

            foreach (string entry in backup_all_files)
            {
                string extension = Path.GetExtension(entry).ToLower();
                switch (extension)
                {
                    case ".xml":
                        xml_files.Add(entry);
                        break;
                    case ".apk":
                        apk_files.Add(entry);
                        break;
                    case ".tar":
                        tar_files.Add(entry);
                        break;
                    case ".db":
                        db_files.Add(entry);
                        break;
                    case ".enc":
                        enc_files.Add(entry);
                        break;
                    default:
                        unk_files.Add(entry);
                        break;
                }
            }

            HybridDictionary decrypt_material_dict = new HybridDictionary();
            Decryptor decryptor = new Decryptor(user_password);

            Console.WriteLine("parsing XML files...");
            foreach (string entry in xml_files)
            {
                string filename = Path.GetFileName(entry);
                Console.WriteLine("parsing xml " + filename);
                if (filename.ToLower() == "info.xml")
                {
                    decrypt_material_dict = parse_info_xml(entry, ref decryptor, decrypt_material_dict);
                }
                else
                {
                    decrypt_material_dict = parse_xml(entry, decrypt_material_dict);
                }
            }

            decryptor.crypto_init();
            if (decryptor.good == false)
            {
                Console.WriteLine("decryption key is not good...");
                return;
            }

            if (apk_files.Count > 0)
            {
                Console.WriteLine("copying APK to destination...");
                string data_apk_dir = Path.Combine(dest_path_out, @"data\app");
                Directory.CreateDirectory(data_apk_dir);

                done_list = new List<string>();
                foreach (string entry in apk_files)
                {
                    string filename = Path.GetFileName(entry);
                    Console.WriteLine("working on " + filename);
                    string dest_file = Path.Combine(data_apk_dir, filename + "-1");
                    Directory.CreateDirectory(dest_file);
                    dest_file = Path.Combine(dest_file, "base.apk");
                    File.Copy(entry, dest_file);
                    done_list.Add(entry);
                }

                foreach (string entry in done_list)
                {
                    apk_files.Remove(entry);
                }
            }

            if (tar_files.Count > 0)
            {
                Console.WriteLine("decrypting and un-TAR-ing packages to destination...");
                string data_app_dir = Path.Combine(dest_path_out, @"data\data");
                Directory.CreateDirectory(data_app_dir);

                done_list = new List<string>();
                foreach (string entry in tar_files)
                {
                    Console.WriteLine("working on " + Path.GetFileName(entry));
                    byte[] cleartext = null;
                    string directory = Path.GetDirectoryName(entry);
                    string filename = Path.GetFileNameWithoutExtension(entry);
                    string skey = Path.Combine(directory, filename);
                    if (decrypt_material_dict.Contains(skey))
                    {
                        done_list.Add(entry);
                        DecryptMaterial dec_material = (DecryptMaterial)decrypt_material_dict[skey];
                        cleartext = decryptor.decrypt_package(dec_material, File.ReadAllBytes(entry));
                    }
                    else Console.WriteLine("entry '{0}' has no decrypt material!", skey);

                    if (cleartext != null)
                    {
                        using (MemoryStream ms = new MemoryStream(cleartext))
                        {
                            TAR_Extract(ms, data_app_dir);
                        }
                    }
                    else if (File.Exists(entry))
                    {
                        using (StreamReader sr = new StreamReader(entry))
                        {
                            TAR_Extract(sr.BaseStream, data_app_dir);
                        }
                    }
                }

                foreach (string entry in done_list)
                {
                    tar_files.Remove(entry);
                }
            }

            if (db_files.Count > 0)
            {
                Console.WriteLine("decrypting database DB files to destination...");
                string data_app_dir = Path.Combine(dest_path_out, "db");
                Directory.CreateDirectory(data_app_dir);

                done_list = new List<string>();
                foreach (string entry in db_files)
                {
                    Console.WriteLine("working on " + Path.GetFileName(entry));
                    byte[] cleartext = null;
                    string directory = Path.GetDirectoryName(entry);
                    string filename = Path.GetFileNameWithoutExtension(entry);
                    string skey = Path.Combine(directory, filename);
                    if (decrypt_material_dict.Contains(skey))
                    {
                        done_list.Add(entry);
                        DecryptMaterial dec_material = (DecryptMaterial)decrypt_material_dict[skey];
                        cleartext = decryptor.decrypt_package(dec_material, File.ReadAllBytes(entry));
                    }
                    else Console.WriteLine("entry '{0}' has no decrypt material!", skey);

                    if (cleartext != null)
                    {
                        string dest_file = Path.Combine(data_app_dir, Path.GetFileName(entry));
                        File.WriteAllBytes(dest_file, cleartext);
                    }
                }

                foreach (string entry in done_list)
                {
                    db_files.Remove(entry);
                }
            }

            if (enc_files.Count > 0)
            {
                Console.WriteLine("decrypting multimedia ENC files to destination...");

                string asterisk = @"|/-\-";

                done_list = new List<string>();
                for (int i = 1; i <= enc_files.Count; i++)
                {
                    string entry = enc_files[i - 1];
                    byte[] cleartext = null;
                    DecryptMaterial dec_material = null;
                    string directory = Path.GetDirectoryName(entry);
                    string filename = Path.GetFileNameWithoutExtension(entry);
                    string skey = Path.Combine(directory, filename);
                    if (decrypt_material_dict.Contains(skey))
                    {
                        done_list.Add(entry);
                        dec_material = (DecryptMaterial)decrypt_material_dict[skey];
                        string aString = String.Format("{0} of {1}: {2}",
                            i, enc_files.Count,
                            Path.GetFileName(dec_material.path));
                        aString = aString.PadRight(Console.WindowWidth - 2).Substring(0, Console.WindowWidth - 2);
                        Console.Write("\r{0}{1}", aString, asterisk[i % asterisk.Length]);
                        cleartext = decryptor.decrypt_file(dec_material, File.ReadAllBytes(entry));
                    }
                    else Console.WriteLine("entry '{0}' has no decrypt material!", skey);

                    if (cleartext != null && dec_material != null)
                    {
                        string dest_file = dest_path_out;
                        string tmp_path = dec_material.path.TrimStart(new char[] { '\\', '/' });
                        dest_file = Path.Combine(dest_file, tmp_path);
                        string dest_dir = Directory.GetParent(dest_file).FullName;
                        Directory.CreateDirectory(dest_dir);
                        File.WriteAllBytes(dest_file, cleartext);
                    }
                }
                if (enc_files.Count > 0)
                    Console.Write("\r");

                foreach (string entry in done_list)
                {
                    enc_files.Remove(entry);
                }
            }


            if (unk_files.Count > 0)
            {
                Console.WriteLine("copying unmanaged files to destination...");
                string data_unk_dir = Path.Combine(dest_path_out, "misc");
                Directory.CreateDirectory(data_unk_dir);

                done_list = new List<string>();
                foreach (string entry in unk_files)
                {
                    string common_path = FindCommonPath(new List<string>()
                    {
                        entry,
                        backup_path_in
                    });
                    string relative_path = entry.Replace(common_path, "");
                    relative_path = relative_path.TrimStart(new char[] { '\\', '/' });
                    string dest_file = Path.Combine(data_unk_dir, relative_path);
                    Directory.CreateDirectory(Directory.GetParent(dest_file).FullName);
                    File.Copy(entry, dest_file);
                    done_list.Add(entry);
                }

                foreach (string entry in done_list)
                {
                    unk_files.Remove(entry);
                }
            }

            foreach (string entry in apk_files)
            {
                string filename = Path.GetFileName(entry);
                Console.WriteLine("APK file not handled: " + filename);
            }

            foreach (string entry in tar_files)
            {
                string filename = Path.GetFileName(entry);
                Console.WriteLine("TAR file not handled: " + filename);
            }

            foreach (string entry in db_files)
            {
                string filename = Path.GetFileName(entry);
                Console.WriteLine("DB file not handled: " + filename);
            }

            foreach (string entry in enc_files)
            {
                string filename = Path.GetFileName(entry);
                Console.WriteLine("ENC file not handled: " + filename);
            }

            foreach (string entry in unk_files)
            {
                string filename = Path.GetFileName(entry);
                Console.WriteLine("UNK file not handled: " + filename);
            }

            Console.WriteLine("DONE!");
        }
    }

    /// <summary>
    /// Decrypting info for a single file.
    /// </summary>
    internal class DecryptMaterial
    {
        #region Some useful functions

        /// <summary>
        /// Every byte of data is converted into the corresponding 2-digit hex representation.
        /// The resulting string is therefore twice as long as the length of data.
        /// </summary>
        /// <param name="ba">Data to convert.</param>
        /// <returns>Return the hexadecimal representation of the binary data.</returns>
        /// <seealso cref="https://docs.python.org/2/library/binascii.html"/>
        internal static string hexlify(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        /// <summary>
        /// Convert an hexadecimal string to binary array data.
        /// hexstr must contain an even number of hexadecimal digits (which can be upper or lower case).
        /// </summary>
        /// <param name="hexvalue">Hexadecimal string.</param>
        /// <returns>Return the binary data represented by the hexadecimal string hexstr.</returns>
        /// <seealso cref="https://stackoverflow.com/questions/1459006/is-there-a-c-sharp-equivalent-to-pythons-unhexlify"/>
        /// <seealso cref="https://docs.python.org/2/library/binascii.html"/>
        internal static byte[] unhexlify(string hexvalue)
        {
            if (hexvalue.Length % 2 != 0)
                hexvalue = "0" + hexvalue;
            int len = hexvalue.Length / 2;
            byte[] bytes = new byte[len];
            for (int i = 0; i < len; i++)
            {
                string byteString = hexvalue.Substring(2 * i, 2);
                bytes[i] = Convert.ToByte(byteString, 16);
            }
            return bytes;
        }

        #endregion

        internal DecryptMaterial(string type_name)
        {
            this.type_name = type_name;
            this.name = null;
        }

        internal string type_name { get; set; }

        internal string name { get; set; }

        internal string _encMsgV3;
        internal byte[] _encMsgV3Bytes;

        internal string encMsgV3
        {
            get { return _encMsgV3; }
            set
            {
                if (!String.IsNullOrEmpty(value))
                {
                    this._encMsgV3 = value;
                    this._encMsgV3Bytes = unhexlify(value);
                    if (this._encMsgV3Bytes.Length != 48)
                        Console.WriteLine("encMsgV3 should be 48 bytes long!");
                }
            }
        }

        internal string _iv;
        internal byte[] _ivBytes;

        internal string iv
        {
            get { return _iv; }
            set
            {
                if (!String.IsNullOrEmpty(value))
                {
                    this._iv = value;
                    this._ivBytes = unhexlify(value);
                    if (this._ivBytes.Length != 16)
                        Console.WriteLine("iv should be 16 bytes long!");
                }
            }
        }

        string _path = null;

        internal string path
        {
            get { return _path; }
            set
            {
                if (!String.IsNullOrEmpty(value))
                    this._path = value;
                else
                    Console.WriteLine("empty file path!");
            }
        }

        internal bool do_check()
        {
            if (this.name != null && (this.encMsgV3 != null || this.iv != null))
                return true;
            else return false;
        }
    }

    /// <summary>
    /// Decrypting routines.
    /// </summary>
    internal class Decryptor
    {
        #region Decrypting routines

        const int count = 5000;
        const int dklen = 32;

        /// <summary>
        /// The function can be used to generate a hashed version of a user-provided password 
        /// to store in a database for authentication purposes.
        /// </summary>
        /// <param name="password">The secret password to generate the key from.</param>
        /// <param name="salt">A (byte) string to use for better protection from dictionary attacks.</param>
        /// <param name="dklen">The cumulative length of the keys to produce.</param>
        /// <param name="count">Iteration count.</param>
        /// <returns>A byte string of length dklen that can be used as key material.</returns>
        /// <seealso cref="https://stackoverflow.com/questions/18648084/rfc2898-pbkdf2-with-sha256-as-digest-in-c-sharp"/>
        /// <seealso cref="https://pycryptodome.readthedocs.io/en/latest/src/protocol/kdf.html"/>
        static byte[] PBKDF2_SHA256_GetBytes(byte[] password, byte[] salt, int dklen, int count)
        {
            // NOTE: The iteration count should be as high as possible without causing
            // unreasonable delay. Note also that the password and salt are byte arrays, not strings.
            // After use, the password and salt should be cleared (with Array.Clear)

            using (var hmac = new System.Security.Cryptography.HMACSHA256(password))
            {
                int hashLength = hmac.HashSize / 8;
                if ((hmac.HashSize & 7) != 0)
                    hashLength++;
                int keyLength = dklen / hashLength;
                if ((long)dklen > (0xFFFFFFFFL * hashLength) || dklen < 0)
                    throw new ArgumentOutOfRangeException("dklen");
                if (dklen % hashLength != 0)
                    keyLength++;
                byte[] extendedkey = new byte[salt.Length + 4];
                Buffer.BlockCopy(salt, 0, extendedkey, 0, salt.Length);
                using (var ms = new System.IO.MemoryStream())
                {
                    for (int i = 0; i < keyLength; i++)
                    {
                        extendedkey[salt.Length] = (byte)(((i + 1) >> 24) & 0xFF);
                        extendedkey[salt.Length + 1] = (byte)(((i + 1) >> 16) & 0xFF);
                        extendedkey[salt.Length + 2] = (byte)(((i + 1) >> 8) & 0xFF);
                        extendedkey[salt.Length + 3] = (byte)(((i + 1)) & 0xFF);
                        byte[] u = hmac.ComputeHash(extendedkey);
                        Array.Clear(extendedkey, salt.Length, 4);
                        byte[] f = u;
                        for (int j = 1; j < count; j++)
                        {
                            u = hmac.ComputeHash(u);
                            for (int k = 0; k < f.Length; k++)
                            {
                                f[k] ^= u[k];
                            }
                        }
                        ms.Write(f, 0, f.Length);
                        Array.Clear(u, 0, u.Length);
                        Array.Clear(f, 0, f.Length);
                    }
                    byte[] dk = new byte[dklen];
                    ms.Position = 0;
                    ms.Read(dk, 0, dklen);
                    ms.Position = 0;
                    for (long i = 0; i < ms.Length; i++)
                    {
                        ms.WriteByte(0);
                    }
                    Array.Clear(extendedkey, 0, extendedkey.Length);
                    return dk;
                }
            }
        }

        /// <summary>
        /// AES in "CounTer Mode" (CTR).
        /// The method works both for encryption and decryption.
        /// </summary>
        /// <param name="key">The secret key to use in the symmetric cipher.</param>
        /// <param name="salt">A (byte) string to use for better protection from dictionary attacks.</param>
        /// <param name="inputStream">The input Stream.</param>
        /// <param name="outputStream">The output Stream.</param>
        /// <seealso cref="https://stackoverflow.com/questions/6374437/can-i-use-aes-in-ctr-mode-in-net"/>
        /// <seealso cref="https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html"/>
        static void AES_CTR_Transform(byte[] key, byte[] salt, Stream inputStream, Stream outputStream)
        {
            SymmetricAlgorithm aes =
                new AesManaged { Mode = CipherMode.ECB, Padding = PaddingMode.None };

            int blockSize = aes.BlockSize / 8;

            if (salt.Length != blockSize)
            {
                throw new ArgumentException(
                    string.Format(
                        "Salt size must be same as block size (actual: {0}, expected: {1})",
                        salt.Length, blockSize));
            }

            byte[] counter = (byte[])salt.Clone();

            Queue<byte> xorMask = new Queue<byte>();

            var zeroIv = new byte[blockSize];
            ICryptoTransform counterEncryptor = aes.CreateEncryptor(key, zeroIv);

            int b;
            while ((b = inputStream.ReadByte()) != -1)
            {
                if (xorMask.Count == 0)
                {
                    var counterModeBlock = new byte[blockSize];

                    counterEncryptor.TransformBlock(
                        counter, 0, counter.Length, counterModeBlock, 0);

                    for (var i2 = counter.Length - 1; i2 >= 0; i2--)
                    {
                        if (++counter[i2] != 0)
                        {
                            break;
                        }
                    }

                    foreach (var b2 in counterModeBlock)
                    {
                        xorMask.Enqueue(b2);
                    }
                }

                var mask = xorMask.Dequeue();
                outputStream.WriteByte((byte)(((byte)b) ^ mask));
            }
        }

        #endregion

        internal Decryptor(string password)
        {
            this._upwd = password;
            this._good = false;
            this._e_perbackupkey = null;
            this._pwkey_salt = null;
            this._type_attch = 0;
            this._checkMsg = null;
            this._bkey = null;
            this._bkey_sha256 = null;
        }

        string _upwd;
        bool _good;
        string _e_perbackupkey;
        byte[] _e_perbackupkeyBytes;
        string _pwkey_salt;
        byte[] _pwkey_saltBytes;
        int _type_attch;
        string _checkMsg;
        byte[] _checkMsgBytes;
        string _bkey;
        byte[] _bkeyBytes;
        byte[] _bkey_sha256;

        internal bool good
        {
            get { return _good; }
            private set { _good = value; }
        }

        internal int type_attch
        {
            get { return _type_attch; }
            set { _type_attch = value; }
        }

        internal string e_perbackupkey
        {
            get { return _e_perbackupkey; }
            set
            {
                if (!String.IsNullOrEmpty(value))
                {
                    this._e_perbackupkey = value;
                    this._e_perbackupkeyBytes = DecryptMaterial.unhexlify(value);
                    if (this._e_perbackupkeyBytes.Length != 48)
                        Console.WriteLine("e_perbackupkey should be 48 bytes long!");
                }
            }
        }

        internal string pwkey_salt
        {
            get { return _pwkey_salt; }
            set
            {
                if (!String.IsNullOrEmpty(value))
                {
                    this._pwkey_salt = value;
                    this._pwkey_saltBytes = DecryptMaterial.unhexlify(value);
                    if (this._pwkey_saltBytes.Length != 32)
                        Console.WriteLine("pwkey_salt should be 32 bytes long!");
                }
            }
        }

        internal string checkMsg
        {
            get { return _checkMsg; }
            set
            {
                if (!String.IsNullOrEmpty(value))
                {
                    this._checkMsg = value;
                    this._checkMsgBytes = DecryptMaterial.unhexlify(value);
                    if (this._checkMsgBytes.Length != 64)
                        Console.WriteLine("checkMsg should be 64 bytes long!");
                }
            }
        }

        internal string bkey
        {
            get { return _bkey; }
            private set
            {
                if (!String.IsNullOrEmpty(value))
                {
                    this._bkey = value;
                    this._bkeyBytes = DecryptMaterial.unhexlify(value);
                    if (this._bkeyBytes.Length != 32)
                        Console.WriteLine("bkey should be 32 bytes long!");
                }
            }
        }

        void __decrypt_bkey_v4()
        {
            throw new NotImplementedException();
        }

        internal void crypto_init()
        {
            if (this.good == true)
            {
                Console.WriteLine("crypto_init: already done with success!");
                return;
            }

            if (this.type_attch != 3)
            {
                Console.WriteLine("crypto_init: type_attch *should be* 3!");
                return;
            }

            if (!String.IsNullOrEmpty(this.e_perbackupkey) && !String.IsNullOrEmpty(this.pwkey_salt))
            {
                Console.WriteLine("crypto_init: using version 4");
                __decrypt_bkey_v4();
            }
            else
            {
                Console.WriteLine("crypto_init: using version 3");
                this._bkey = this._upwd;
            }

            var passwordBytes = Encoding.UTF8.GetBytes(this._bkey);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
            this._bkey_sha256 = passwordBytes.Take(16).ToArray();
            Console.WriteLine("SHA256(BKEY)[{0}] = {1}", this._bkey_sha256.Length,
                        DecryptMaterial.hexlify(this._bkey_sha256));

            byte[] salt = this._checkMsgBytes.Skip(32).ToArray();
            Console.WriteLine("SALT[{0}] = {1}", salt.Length, DecryptMaterial.hexlify(salt));

            byte[] res = PBKDF2_SHA256_GetBytes(Encoding.UTF8.GetBytes(this._bkey), salt, Decryptor.dklen, Decryptor.count);
            Console.WriteLine("KEY check expected = {0}",
                            DecryptMaterial.hexlify(this._checkMsgBytes.Take(32).ToArray()));
            Console.WriteLine("RESULT = {0}", DecryptMaterial.hexlify(res));

            if (res.SequenceEqual(this._checkMsgBytes.Take(32)) == true)
            {
                Console.WriteLine("OK, backup key is correct!");
                this.good = true;
            }
            else
            {
                Console.WriteLine("KO, backup key is wrong!");
                this.good = false;
            }
        }

        internal byte[] decrypt_package(DecryptMaterial dec_material, byte[] data)
        {
            if (this.good == false)
                Console.WriteLine("well, it is hard to decrypt with a wrong key.");

            if (String.IsNullOrEmpty(dec_material.encMsgV3))
            {
                Console.WriteLine("cannot decrypt with an empty encMsgV3!");
                return null;
            }

            byte[] salt = dec_material._encMsgV3Bytes.Take(32).ToArray();
            byte[] counter_iv = dec_material._encMsgV3Bytes.Skip(32).ToArray();

            byte[] key = PBKDF2_SHA256_GetBytes(Encoding.UTF8.GetBytes(this._bkey), salt, Decryptor.dklen, Decryptor.count);

            MemoryStream output = new MemoryStream();
            MemoryStream input = new MemoryStream(data);
            AES_CTR_Transform(key, counter_iv, input, output);

            return output.ToArray();
        }

        internal byte[] decrypt_file(DecryptMaterial dec_material, byte[] data)
        {
            if (this.good == false)
                Console.WriteLine("well, it is hard to decrypt with a wrong key.");

            if (String.IsNullOrEmpty(dec_material.iv))
            {
                Console.WriteLine("cannot decrypt with an empty iv!");
                return null;
            }

            MemoryStream output = new MemoryStream();
            MemoryStream input = new MemoryStream(data);
            AES_CTR_Transform(this._bkey_sha256, dec_material._ivBytes, input, output);

            return output.ToArray();
        }
    }
}
