namespace AuthManual.Models
{
    public class UserClaimsViewModel
    {
        public UserClaimsViewModel()
        {
            UserClaims = new List<UserClaim>();
        }

        public string UserId { get; set; }
        public List<UserClaim> UserClaims { get; set; }
    }

    public class UserClaim // for individual user claim
    {
        public string? ClaimType { get; set; }
        public bool IsSelected  { get; set; }
    }
}
