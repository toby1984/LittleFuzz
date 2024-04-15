package de.codesourcery.littlefuzz.core;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.Optional;
import org.apache.commons.lang3.Validate;

/**
 * A <code>IRuleResolver</code> that wraps another resolver and
 * will try to recursively instantiate and fuzz any POJO
 * that comes with a no-arguments constructor.
 *
 * @author tobias.gierke@code-sourery.de
 */
public class RecursiveRuleResolver implements IRuleResolver
{
    private final IRuleResolver delegate;

    public RecursiveRuleResolver(IRuleResolver delegate)
    {
        Validate.notNull( delegate, "delegate must not be null" );
        this.delegate = delegate;
    }

    @Override
    public IFuzzingRule getRule(Fuzzer.IContext context)
    {
        IFuzzingRule result = delegate.getRule(context);
        if ( result == null && isObject( context.getProperty() ) ) {
            final Optional<Constructor<?>> cnstr = getConstructor( context.getProperty() );
            if ( cnstr.isPresent() ) {
                cnstr.get().setAccessible( true );
                return (context1, setter) -> {
                    try
                    {
                        final Object newValue = cnstr.get().newInstance();
                        context1.getFuzzer().fuzz( newValue, context1.includeInherited() );
                        setter.set( newValue );
                    }
                    catch( InstantiationException | IllegalAccessException | InvocationTargetException e )
                    {
                        throw new RuntimeException( e );
                    }
                };
            }
        }
        return result;
    }

    private Optional<Constructor<?>> getConstructor(IProperty property) {

        return Arrays.stream( property.getType().getDeclaredConstructors() )
            .filter( x -> x.getParameterCount() == 0 ).findFirst();
    }

    private boolean isObject(IProperty property) {
        final Class<?> clazz = property.getDeclaringClass();
        return ! clazz.isEnum() &&
            ! clazz.isAnnotation() &&
            ! clazz.isArray() &&
            ! clazz.isInterface() &&
            ! clazz.isPrimitive() &&
            ! clazz.isRecord() &&
            ! clazz.isSynthetic() &&
            ! isWrapperType( clazz );
    }

    private static boolean isWrapperType(Class<?> type)
    {
        return type == Integer.class || type == Long.class || type == Boolean.class || type == Short.class
         || type == Byte.class || type == Character.class || type == Float.class || type == Double.class
         || type == Void.class;
    }
}