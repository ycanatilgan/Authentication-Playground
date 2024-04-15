using Authentication_Playground_.Data;
using Authentication_Playground_.Models;
using Fido2NetLib;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Fido2Identity
{
    public class Fido2Storage
    {
        AppDbContext _dbContext;

        public Fido2Storage(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public List<FidoStoredCredential> GetCredentialsByUserHandle(byte[] UserHandle)
        {
            return _dbContext.FidoStoredCredentials.Where(c => c.UserHandle == UserHandle).ToList();
        }

        public async Task RemoveCredentialsByUsername(string username)
        {
            var item = await _dbContext.FidoStoredCredentials.Where(c => c.Username == username).FirstOrDefaultAsync();
            if (item != null)
            {
                _dbContext.FidoStoredCredentials.Remove(item);
                await _dbContext.SaveChangesAsync();
            }
        }

        public async Task RemoveCredentialsById(int id)
        {
            var item = await _dbContext.FidoStoredCredentials.Where(c => c.ID == id).FirstOrDefaultAsync();
            if (item != null)
            {
                _dbContext.FidoStoredCredentials.Remove(item);
                await _dbContext.SaveChangesAsync();
            }
        }

        public async Task<FidoStoredCredential> GetCredentialById(byte[] id)
        {
            var credentialIdString = Base64Url.Encode(id);
            credentialIdString += "=";
            credentialIdString = credentialIdString.Replace('-', '+');
            credentialIdString = credentialIdString.Replace('_', '/');
            //byte[] credentialIdStringByte = Base64Url.Decode(credentialIdString);

            var cred = await _dbContext.FidoStoredCredentials
                .Where(c => c.DescriptorJson.Contains(credentialIdString)).FirstOrDefaultAsync();

            return cred;
        }

        public Task<List<FidoStoredCredential>> GetCredentialsByUserHandleAsync(byte[] userHandle)
        {
            return Task.FromResult(_dbContext.FidoStoredCredentials.Where(c => c.UserHandle.SequenceEqual(userHandle)).ToList());
        }

        public async Task UpdateCounter(byte[] credentialId, uint counter)
        {
            var credentialIdString = Base64Url.Encode(credentialId);
            credentialIdString += "=";
            credentialIdString = credentialIdString.Replace('-', '+');
            credentialIdString = credentialIdString.Replace('_', '/');

            var cred = await _dbContext.FidoStoredCredentials
                .Where(c => c.DescriptorJson.Contains(credentialIdString)).FirstOrDefaultAsync();

            cred.SignatureCounter = counter;
            cred.LastLogin = DateTime.Now;
            await _dbContext.SaveChangesAsync();
        }

        public async Task AddCredentialToUser(Fido2User user, FidoStoredCredential credential)
        {
            credential.UserId = user.Id;
            _dbContext.FidoStoredCredentials.Add(credential);
            await _dbContext.SaveChangesAsync();
        }

        public async Task<List<Fido2User>> GetUsersByCredentialIdAsync(byte[] credentialId)
        {
            var credentialIdString = Base64Url.Encode(credentialId);
            //byte[] credentialIdStringByte = Base64Url.Decode(credentialIdString);

            var cred = await _dbContext.FidoStoredCredentials
                .Where(c => c.DescriptorJson.Contains(credentialIdString)).FirstOrDefaultAsync();

            if (cred == null)
            {
                return new List<Fido2User>();
            }

            return await _dbContext.Users
                .Where(u => Encoding.UTF8.GetBytes(u.UserHandle)
                .SequenceEqual(cred.UserId))
                .Select(u => new Fido2User
                {
                    DisplayName = u.Username,
                    Name = u.Username,
                    Id = Encoding.UTF8.GetBytes(u.UserHandle) // byte representation of userID is required
                }).ToListAsync();
        }
    }
}