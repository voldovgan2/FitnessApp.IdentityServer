using System;
using System.Collections.Generic;
using System.Linq;

namespace FitnessApp.IdentityServer.Models.Account
{
    public class RegisterViewModel : RegisterInputViewModel
    {
        public IEnumerable<ExternalProvider> ExternalProviders { get; set; } = Enumerable.Empty<ExternalProvider>();
        public IEnumerable<ExternalProvider> VisibleExternalProviders => ExternalProviders.Where(x => !String.IsNullOrWhiteSpace(x.DisplayName));
    }
}
