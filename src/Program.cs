using System;

namespace kobackupdec
{
    class Program
    {
        const string VERSION = "2019-10-30";

        static void Main(string[] args)
        {
            string description = "HUAWEI KoBackup decryptor .NET version " + VERSION;

            if (args.Length != 3)
            {
                Console.WriteLine("usage: kobackupdec.exe password backup_path dest_path");
                Console.WriteLine();
                Console.WriteLine(description);
                Console.WriteLine();
                Console.WriteLine("  password       user password for the backup");
                Console.WriteLine("  backup_path    backup folder");
                Console.WriteLine("  dest_path      decrypted backup folder");
                return;
            }

            string user_password = args[0];
            string backup_path_in = args[1];
            string dest_path_out = args[2];

            kobackupdec.decrypt(user_password, backup_path_in, dest_path_out);
        }
    }
}
