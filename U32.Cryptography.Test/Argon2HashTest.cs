using System.Text;

namespace U32.Cryptography.Test;

public class Argon2HashTest
{
    [Theory]
    [InlineData("password123")]
    [InlineData("PA$$w0rd12three")]
    public void TwoHashesDoNotMatch(string password)
    {
        var hashes = new Argon2Hash[2];
        {
            hashes[0] = Argon2Hash.FromArgon2D(Encoding.UTF8.GetBytes(password));
            hashes[1] = Argon2Hash.FromArgon2D(Encoding.UTF8.GetBytes(password));

            Assert.NotEqual(hashes[0], hashes[1]);
        }

        {
            hashes[0] = Argon2Hash.FromArgon2I(Encoding.UTF8.GetBytes(password));
            hashes[1] = Argon2Hash.FromArgon2I(Encoding.UTF8.GetBytes(password));

            Assert.NotEqual(hashes[0], hashes[1]);
        }

        {
            hashes[0] = Argon2Hash.FromArgon2Id(Encoding.UTF8.GetBytes(password));
            hashes[1] = Argon2Hash.FromArgon2Id(Encoding.UTF8.GetBytes(password));

            Assert.NotEqual(hashes[0], hashes[1]);
        }
    }

    [Theory]
    [InlineData("password123")]
    [InlineData("PA$$w0rd12three")]
    public void Argon2Id_HashesMatch(string password)
    {
        {
            var source = Argon2Hash.FromArgon2D(Encoding.UTF8.GetBytes(password));
            var other = Argon2Hash.FromBytes(source.Bytes, source.Salt.Length);

            Assert.Equal(source, other);
        }

        {
            var source = Argon2Hash.FromArgon2I(Encoding.UTF8.GetBytes(password));
            var other = Argon2Hash.FromBytes(source.Bytes, source.Salt.Length);

            Assert.Equal(source, other);
        }

        {
            var source = Argon2Hash.FromArgon2Id(Encoding.UTF8.GetBytes(password));
            var other = Argon2Hash.FromBytes(source.Bytes, source.Salt.Length);

            Assert.Equal(source, other);
        }
    }
}