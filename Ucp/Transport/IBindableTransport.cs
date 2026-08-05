using System.Net;

namespace Ucp.Transport
{

    internal interface IBindableTransport : ITransport
    {

        EndPoint LocalEndPoint { get; }

        void Start(int port);

        void Stop();
    }
}
