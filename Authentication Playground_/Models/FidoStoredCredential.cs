using Fido2NetLib.Objects;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.ComponentModel.DataAnnotations.Schema;

namespace Authentication_Playground_.Models
{
    public class FidoStoredCredential
    {
        public int ID { get; set; }
        public string Username { get; set; }
        public byte[] UserId { get; set; }
        public byte[] PublicKey { get; set; }
        public byte[] UserHandle { get; set; }
        public uint SignatureCounter { get; set; }
        public string CredType { get; set; }
        public DateTime RegDate { get; set; }
        public DateTime LastLogin { get; set; }
        public Guid AaGuid { get; set; }
        public string DeviceInfo { get; set; }

        [NotMapped]
        public PublicKeyCredentialDescriptor Descriptor
        {
            get { return string.IsNullOrWhiteSpace(DescriptorJson) ? null : JsonConvert.DeserializeObject<PublicKeyCredentialDescriptor>(DescriptorJson); }
            set { DescriptorJson = JsonConvert.SerializeObject(value); }
        }
        public string DescriptorJson { get; set; }
    }
}