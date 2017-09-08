using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ActionConstraints;
using Microsoft.AspNetCore.Routing;

namespace MonkeyLogon.Helpers
{
    public sealed class QueryStringRequiredAttribute : ActionMethodSelectorAttribute
    {
        private readonly string name;

        public QueryStringRequiredAttribute(string name)
        {
            this.name = name;
        }

        public override bool IsValidForRequest(RouteContext routeContext, ActionDescriptor action)
        {
            return !string.IsNullOrEmpty(routeContext.HttpContext.Request.Query[this.name]);
        }
    }
}