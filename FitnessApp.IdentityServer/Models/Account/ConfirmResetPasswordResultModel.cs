using System.Collections.Generic;

namespace FitnessApp.IdentityServer.Models.Account
{
    public class ConfirmResetPasswordResultModel
    {
        public bool Result { get; set; }
        public IEnumerable<string> Data { get; set; }

        public ConfirmResetPasswordResultModel(bool result, string data)
        {
            Result = result;
            Data = new string[] { data };
        }

        public ConfirmResetPasswordResultModel(bool result, IEnumerable<string> data)
        {
            Result = result;
            Data = data;
        }
    }
}