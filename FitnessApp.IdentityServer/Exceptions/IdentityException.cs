using System;

namespace FitnessApp.IdentityServer.Exceptions
{
    public class IdentityException : Exception
    {
        public IdentityException(string message) : base(message) { }
    }
}
