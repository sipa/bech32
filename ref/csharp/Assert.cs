using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace csharp
{
    public static class Assert
    {
        public static void Equal<T>(T a, T b)
        {
            if (!a.Equals(b))
                throw new Exception("a != b");
        }

        public static T Throws<T>(Action act) where T : Exception
        {
            try
            {
                act();
            }
            catch (T ex)
            {
                return ex;
            }
            throw new Exception("Should have thrown");
        }
    }
}
