using Libplanet.Stun.Attributes;
using Xunit;

namespace Libplanet.Tests.Stun.Attributes
{
    public class UserNameTest
    {
        [Fact]
        public void EncodeToBytes()
        {
            var attr = new Username("ae0633cd58ba097a1167c6d2cc4e236db52256a40d565f11edf76c02d13db93c");
            Assert.Equal(
                new byte[]
                {
                    0x00, 0x06, 0x00, 0x40, 0x61, 0x65, 0x30, 0x36, 0x33, 0x33,
                    0x63, 0x64, 0x35, 0x38, 0x62, 0x61, 0x30, 0x39, 0x37, 0x61,
                    0x31, 0x31, 0x36, 0x37, 0x63, 0x36, 0x64, 0x32, 0x63, 0x63,
                    0x34, 0x65, 0x32, 0x33, 0x36, 0x64, 0x62, 0x35, 0x32, 0x32,
                    0x35, 0x36, 0x61, 0x34, 0x30, 0x64, 0x35, 0x36, 0x35, 0x66,
                    0x31, 0x31, 0x65, 0x64, 0x66, 0x37, 0x36, 0x63, 0x30, 0x32,
                    0x64, 0x31, 0x33, 0x64, 0x62, 0x39, 0x33, 0x63,
                },
                attr.ToByteArray());
        }
    }
}
