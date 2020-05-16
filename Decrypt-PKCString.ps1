function Decrypt-PKCString{
    param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$EncryptedString,

        [Parameter(Mandatory=$true,Position=2)]
        [string]$DecryptionKey,

        [Parameter(Mandatory=$true,Position=3)]
        [byte[]]$Salt,

        [Parameter(Mandatory=$true,Position=4)]
        [int]$MD5Iterations,

        [Parameter(Mandatory=$true,Position=5)]
        [int]$Segments
    )
    Begin{
        Add-Type -TypeDefinition @"
using System;
using System.Security.Cryptography;
using System.Text;

namespace Utility
{
  public class PKCSKeyGenerator
  {
    private byte[] key = new byte[8];
    private byte[] iv = new byte[8];
    private DESCryptoServiceProvider des = new DESCryptoServiceProvider();

    public byte[] Key
    {
      get
      {
        return this.key;
      }
    }

    public byte[] IV
    {
      get
      {
        return this.iv;
      }
    }

    public ICryptoTransform Encryptor
    {
      get
      {
        return this.des.CreateEncryptor(this.key, this.iv);
      }
    }

    public ICryptoTransform Decryptor
    {
      get
      {
        return this.des.CreateDecryptor(this.key, this.iv);
      }
    }

    public PKCSKeyGenerator()
    {
    }

    public PKCSKeyGenerator(string keystring, byte[] salt, int md5iterations, int segments)
    {
      this.Generate(keystring, salt, md5iterations, segments);
    }

    public ICryptoTransform Generate(
      string keystring,
      byte[] salt,
      int md5iterations,
      int segments)
    {
      int num = 16;
      byte[] numArray1 = new byte[num * segments];
      byte[] bytes = Encoding.UTF8.GetBytes(keystring);
      byte[] numArray2 = new byte[bytes.Length + salt.Length];
      Array.Copy((Array) bytes, (Array) numArray2, bytes.Length);
      Array.Copy((Array) salt, 0, (Array) numArray2, bytes.Length, salt.Length);
      MD5 md5 = (MD5) new MD5CryptoServiceProvider();
      byte[] buffer = (byte[]) null;
      byte[] numArray3 = new byte[num + numArray2.Length];
      for (int index1 = 0; index1 < segments; ++index1)
      {
        if (index1 == 0)
        {
          buffer = numArray2;
        }
        else
        {
          Array.Copy((Array) buffer, (Array) numArray3, buffer.Length);
          Array.Copy((Array) numArray2, 0, (Array) numArray3, buffer.Length, numArray2.Length);
          buffer = numArray3;
        }
        for (int index2 = 0; index2 < md5iterations; ++index2)
          buffer = md5.ComputeHash(buffer);
        Array.Copy((Array) buffer, 0, (Array) numArray1, index1 * num, buffer.Length);
      }
      Array.Copy((Array) numArray1, 0, (Array) this.key, 0, 8);
      Array.Copy((Array) numArray1, 8, (Array) this.iv, 0, 8);
      return this.Encryptor;
    }
  }
}
"@       
    }
    Process{
        $decryptor = [Utility.PKCSKeyGenerator]::new($DecryptionKey,$Salt,$MD5Iterations,$Segments).Decryptor
        [byte[]]$inputBuffer = [Convert]::FromBase64String($EncryptedString)
        $decrypted = $decryptor.TransformFinalBlock($inputBuffer, 0, $inputBuffer.Length)
    }
    End{
        [System.Text.Encoding]::UTF8.GetString($decrypted)
    }
}