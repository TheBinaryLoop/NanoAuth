using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace NanoAuth.Extensions
{
    public static class IServiceCollectionExtensions
    {
        public static IServiceCollection ConfigureSettings<TSettings>(this IServiceCollection collection,
            IConfigurationSection section)
            where TSettings : class, new()
        {
            var settings = new TSettings();
            section.Bind(settings);
            collection.AddSingleton(settings);
            return collection;
        }
    }
}