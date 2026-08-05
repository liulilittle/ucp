namespace Ucp
{

    public interface IUcpObject
    {

        uint ConnectionId { get; }

        UcpNetwork Network { get; }
    }
}
