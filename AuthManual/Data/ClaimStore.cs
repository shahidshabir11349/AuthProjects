using System.Security.Claims;

namespace AuthManual.Data
{
    public class ClaimStore
    {
        public static List<Claim> ClaimsList = new List<Claim>()
        {
            new Claim("Create", "Create"),
            new Claim("Edit", "Edit"),
            new Claim("Delete", "Delete"),
        };
    }
}
