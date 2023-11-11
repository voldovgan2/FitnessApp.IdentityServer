using System.Collections.Generic;
using System.Linq;
using Duende.IdentityServer.Models;

namespace FitnessApp.IdentityServer.Models.Home
{
    public class ErrorViewModel
    {
        public ErrorViewModel()
        {
        }

        public ErrorViewModel(string error)
        {
            Errors = new ErrorMessage[] { new ErrorMessage { Error = error } };
        }

        public ErrorViewModel(IEnumerable<string> errors)
        {
            Errors = errors.Select(e => new ErrorMessage { Error = e });
        }

        public IEnumerable<ErrorMessage> Errors { get; set; }
    }
}
