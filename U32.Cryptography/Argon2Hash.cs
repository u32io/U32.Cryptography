using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Konscious.Security.Cryptography;

namespace U32.Cryptography;

/// <summary>
/// The result of an <see cref="Argon2"/> hash function
/// </summary>
/// <example>
/// In order to create a hash, define your <see cref="Argon2Options"/>, or go with the defaults and the then produce a
/// hash, using one of the three algorithms:
/// <code>
/// var hash = Argon2Hash.FromArgon2Id("my_secret_password");
/// </code>
/// After a hash is saved, it must later be retrieved to be verified. It can be created through the bytes retrieved from
/// the serialization source:
/// <code>
/// var hash = Argon2Hash.FromBytes(bytes, 16);
/// </code>
/// The <see cref="Argon2Hash"/> requires a salt. The default salt length is <c>16</c>. Hashing passwords without a
/// randomized salt is both dangerous and irresponsible.
/// </example>
public readonly struct Argon2Hash : IEquatable<Argon2Hash>
{
    private readonly int _saltLength;
    private readonly int _hashLength;
    public readonly byte[] Bytes;

    private Argon2Hash(int saltLength, int hashLength, byte[] bytes)
    {
        _saltLength = saltLength;
        _hashLength = hashLength;
        Bytes = bytes;
    }

    public ReadOnlySpan<byte> Salt => new(Bytes, 0, _saltLength);
    public ReadOnlySpan<byte> Hash => new(Bytes, _saltLength, _hashLength);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(_saltLength, _hashLength, Bytes);

    /// <inheritdoc/>
    public bool Equals(Argon2Hash other) => other.Bytes.SequenceEqual(Bytes);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is Argon2Hash hash && Equals(hash);

    public static bool operator ==(Argon2Hash left, Argon2Hash right) => left.Equals(right);

    public static bool operator !=(Argon2Hash left, Argon2Hash right) => !(left == right);

    public static Argon2Hash FromBytes(byte[] bytes, int saltLength) =>
        new(saltLength, bytes.Length - saltLength, bytes);

    /// <summary>
    /// Produces a <see cref="Argon2Hash"/> via the <see cref="Argon2id"/> algorithm
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Argon2Hash FromArgon2Id(byte[] password) => FromArgon2Id(password, Argon2Options.Default);

    /// <summary>
    /// Produces a <see cref="Argon2Hash"/> via the <see cref="Argon2d"/> algorithm
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Argon2Hash FromArgon2D(byte[] password) => FromArgon2D(password, Argon2Options.Default);

    /// <summary>
    /// Produces a <see cref="Argon2Hash"/> via the <see cref="Argon2i"/> algorithm
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Argon2Hash FromArgon2I(byte[] password) => FromArgon2I(password, Argon2Options.Default);

    /// <param name="password">The password to be hashed</param>
    /// <param name="options"><see cref="Argon2Options"/></param>
    /// <param name="associatedData">
    /// Data associated with the password, such as a user id. For more information see
    /// <see cref="Konscious.Security.Cryptography.Argon2.AssociatedData"/>.
    /// </param>
    /// <param name="knownSecret">
    /// A secret that ought to be kept in a separate location as the passwords, such as a secret key on a different
    /// server. For more information, see <see cref="Konscious.Security.Cryptography.Argon2.KnownSecret"/>.
    /// </param>
    /// <returns></returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Argon2Hash FromArgon2Id(
        byte[] password,
        Argon2Options options,
        byte[]? associatedData = null,
        byte[]? knownSecret = null) => FromAnyArgon2(new Argon2d(password), options, associatedData, knownSecret);

    /// <summary>
    /// Produces a <see cref="Argon2Hash"/>
    /// </summary>
    /// <param name="password">The password to be hashed</param>
    /// <param name="options"><see cref="Argon2Options"/></param>
    /// <param name="associatedData">
    /// Data associated with the password, such as a user id. For more information see
    /// <see cref="Konscious.Security.Cryptography.Argon2.AssociatedData"/>.
    /// </param>
    /// <param name="knownSecret">
    /// A secret that ought to be kept in a separate location as the passwords, such as a secret key on a different
    /// server. For more information, see <see cref="Konscious.Security.Cryptography.Argon2.KnownSecret"/>.
    /// </param>
    /// <returns></returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Argon2Hash FromArgon2I(
        byte[] password,
        Argon2Options options,
        byte[]? associatedData = null,
        byte[]? knownSecret = null) => FromAnyArgon2(new Argon2d(password), options, associatedData, knownSecret);

    /// <summary>
    /// Produces a <see cref="Argon2Hash"/>
    /// </summary>
    /// <param name="password">The password to be hashed</param>
    /// <param name="options"><see cref="Argon2Options"/></param>
    /// <param name="associatedData">
    /// Data associated with the password, such as a user id. For more information see
    /// <see cref="Konscious.Security.Cryptography.Argon2.AssociatedData"/>.
    /// </param>
    /// <param name="knownSecret">
    /// A secret that ought to be kept in a separate location as the passwords, such as a secret key on a different
    /// server. For more information, see <see cref="Konscious.Security.Cryptography.Argon2.KnownSecret"/>.
    /// </param>
    /// <returns></returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Argon2Hash FromArgon2D(
        byte[] password,
        Argon2Options options,
        byte[]? associatedData = null,
        byte[]? knownSecret = null) => FromAnyArgon2(new Argon2d(password), options, associatedData, knownSecret);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Argon2Hash FromAnyArgon2<T>(
        T argon2,
        Argon2Options options,
        byte[]? associatedData = null,
        byte[]? knownSecret = null)
        where T : Argon2
    {
        var salt = new byte[options.SaltLength];
        RandomNumberGenerator.Fill(salt);
        argon2.Salt = salt;
        argon2.Iterations = options.Iterations;
        argon2.MemorySize = options.MemorySize;
        argon2.DegreeOfParallelism = options.DegreeOfParallelism;
        if (associatedData != null) argon2.AssociatedData = associatedData;
        if (knownSecret != null) argon2.KnownSecret = knownSecret;
        return new Argon2Hash(options.SaltLength, options.HashLength, argon2.GetBytes(options.HashLength));
    }
}