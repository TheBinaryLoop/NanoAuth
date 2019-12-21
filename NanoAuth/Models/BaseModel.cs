using System.Collections.Generic;

namespace NanoAuth.Models
{
    public abstract class BaseModel
    {
        public List<string> Errors { get; set; } = new List<string>();
    }
}