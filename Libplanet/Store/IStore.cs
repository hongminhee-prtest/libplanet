using System.Collections.Generic;
using System.Collections.Immutable;
using System.Security.Cryptography;
using Libplanet.Action;
using Libplanet.Blocks;
using Libplanet.Tx;

namespace Libplanet.Store
{
    public interface IStore
    {
        /// <summary>
        /// Lists existing namespaces.
        /// </summary>
        /// <returns>Existing namespaces.</returns>
        IEnumerable<string> ListNamespaces();

        long CountIndex(string @namespace);

        IEnumerable<HashDigest<SHA256>> IterateIndex(string @namespace);

        HashDigest<SHA256>? IndexBlockHash(string @namespace, long index);

        long AppendIndex(string @namespace, HashDigest<SHA256> hash);

        bool DeleteIndex(string @namespace, HashDigest<SHA256> hash);

        void StageTransactionIds(ISet<TxId> txids);

        void UnstageTransactionIds(ISet<TxId> txids);

        IEnumerable<TxId> IterateStagedTransactionIds();

        IEnumerable<TxId> IterateTransactionIds();

        Transaction<T> GetTransaction<T>(TxId txid)
            where T : IAction, new();

        void PutTransaction<T>(Transaction<T> tx)
            where T : IAction, new();

        bool DeleteTransaction(TxId txid);

        IEnumerable<HashDigest<SHA256>> IterateBlockHashes();

        Block<T> GetBlock<T>(HashDigest<SHA256> blockHash)
            where T : IAction, new();

        /// <summary>
        /// Puts the given <paramref name="block"/> in to the store.
        /// </summary>
        /// <param name="block">A <see cref="Block{T}"/> to put into the store.
        /// </param>
        /// <typeparam name="T">An <see cref="IAction"/> class used with
        /// <paramref name="block"/>.</typeparam>
        void PutBlock<T>(Block<T> block)
            where T : IAction, new();

        bool DeleteBlock(HashDigest<SHA256> blockHash);

        AddressStateMap GetBlockStates(HashDigest<SHA256> blockHash);

        void SetBlockStates(
            HashDigest<SHA256> blockHash,
            AddressStateMap states
        );

        /// <summary>
        /// Lookup a state reference, which is a <see cref="Block{T}.Hash"/>
        /// that has the state of the <paramref name="address"/>.
        /// </summary>
        /// <param name="namespace">The namespace to lookup a state reference.
        /// </param>
        /// <param name="address">The <see cref="Address"/> to find lookup.
        /// </param>
        /// <param name="lookupUntil">The upper bound (i.e., the latest block)
        /// of the search range. <see cref="Block{T}"/>s after
        /// <paramref name="lookupUntil"/> are ignored.</param>
        /// <returns>A <see cref="Block{T}.Hash"/> which has the state of the
        /// <paramref name="address"/>.</returns>
        /// <typeparam name="T">An <see cref="IAction"/> class used with
        /// <paramref name="lookupUntil"/>.</typeparam>
        /// <seealso cref="StoreStateReference{T}"/>
        HashDigest<SHA256>? LookupStateReference<T>(
            string @namespace,
            Address address,
            Block<T> lookupUntil)
            where T : IAction, new();

        /// <summary>
        /// Stores a state reference, which is a <see cref="Block{T}.Hash"/>
        /// that has the state of the <see cref="Address"/> for each updated
        /// <see cref="Address"/>es by the <see cref="Transaction{T}"/>s in the
        /// <paramref name="block"/>.</summary>
        /// <param name="namespace">The namespace to store a state reference.
        /// </param>
        /// <param name="addresses">The <see cref="Address"/>es to store state
        /// reference.</param>
        /// <param name="block">The <see cref="Block{T}"/> which has the state
        /// of the <see cref="Address"/>.</param>
        /// <typeparam name="T">An <see cref="IAction"/> class used with
        /// <paramref name="block"/>.</typeparam>
        /// <seealso cref="LookupStateReference{T}"/>
        void StoreStateReference<T>(
            string @namespace,
            IImmutableSet<Address> addresses,
            Block<T> block)
            where T : IAction, new();

        /// <summary>
        /// Forks state references, which are <see cref="Block{T}.Hash"/>es that
        /// have the state of the <see cref="Address"/>es, from
        /// <paramref name="sourceNamespace"/> to
        /// <paramref name="destinationNamespace"/>.
        /// <para>This method copies state references from
        /// <paramref name="sourceNamespace"/> to
        /// <paramref name="destinationNamespace"/> and strips
        /// <paramref name="addressesToStrip"/> of state references after
        /// <paramref name="branchPoint"/>.</para>
        /// </summary>
        /// <param name="sourceNamespace">The namespace of state references to
        /// fork.</param>
        /// <param name="destinationNamespace">The namespace of destination
        /// state references.</param>
        /// <param name="branchPoint">The index of branch point to fork.
        /// </param>
        /// <param name="addressesToStrip">The set of <see cref="Address"/>es
        /// to strip <see cref="Block{T}.Hash"/> after forking.</param>
        /// <typeparam name="T">An <see cref="IAction"/> class used with
        /// <paramref name="branchPoint"/>.</typeparam>
        /// <exception cref="NamespaceNotFoundException">Thrown when the given
        /// <paramref name="sourceNamespace"/> does not exist.</exception>
        /// <seealso cref="LookupStateReference{T}"/>
        /// <seealso cref="StoreStateReference{T}"/>
        void ForkStateReferences<T>(
            string sourceNamespace,
            string destinationNamespace,
            Block<T> branchPoint,
            IImmutableSet<Address> addressesToStrip)
            where T : IAction, new();

        long CountTransactions();

        long CountBlocks();
    }
}
