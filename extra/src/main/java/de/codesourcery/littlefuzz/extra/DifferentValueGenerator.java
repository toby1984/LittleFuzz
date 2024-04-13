package de.codesourcery.littlefuzz.extra;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiPredicate;
import org.apache.commons.lang3.Validate;
import de.codesourcery.littlefuzz.core.IFieldValueGenerator;

/**
 * Helper class that can wrap {@link IFieldValueGenerator field value generators}
 * so that they always generate a value that is not equal to the field's current value.
 *
 * <p>
 * Because equality is a tricky problem and not all Java classes come with a suitable {@link Object#equals(Object)}
 * method, this helper class allows you to register your own {@link #addEqualityRule(Class, BiPredicate) equality rules.}
 * </p>
 * <p>If no suitable rule is configured, the default behaviour of this class is to fall-back to
 * {@link Object#equals(Object)}.</p>
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class DifferentValueGenerator
{
    private static final BiPredicate<Object,Object> ALWAYS_FALSE = (a, b) -> false;

    private final int maxAttempts;

    // Rules describing how to compare values of a specific type.
    private final Map<Class<?>, BiPredicate<Object,Object>> equalityRules = new HashMap<>();

    private BiPredicate<Object,Object> defaultEqualityRule = Objects::equals;

    /**
     * Create instance.
     *
     * @param maxAttempts how often to attempt generating a different value before giving up and throwing a <code>RuntimeException</code>.
     */
    public DifferentValueGenerator(int maxAttempts)
    {
        Validate.isTrue( maxAttempts > 0 );
        this.maxAttempts = maxAttempts;
    }

    /**
     * Wraps an {@link IFieldValueGenerator} so that it never returns the value the current field already has.
     * <p>
     * This method relies on the {@link #addEqualityRule(Class, BiPredicate)}  equality rules} configured on the current fuzzer.
     * </p>
     *
     * @param delegate <code>IFieldValueGenerator</code> to wrap
     * @see #setDefaultEqualityRule(BiPredicate)
     * @see #addEqualityRule(Class, BiPredicate)
     */
    public IFieldValueGenerator wrap(IFieldValueGenerator delegate) {
        return context -> {
            final Object currentValue = context.getFieldValue();
            int retries = maxAttempts;
            while( retries-- > 0 ) {
                final Object newValue = delegate.getValue( context );
                if ( ! getEqualityRule( currentValue, newValue ).test( currentValue, newValue ) ) {
                    return newValue;
                }
            }
            throw new RuntimeException( "Bailing out after failing to come up with a different value for " + currentValue + " for" +
                " " + maxAttempts + " times." );
        };
    }

    private BiPredicate<Object,Object> getEqualityRule(Object a, Object b)
    {
        if ( a == null || b == null ) {
            return ALWAYS_FALSE;
        }
        if ( a.getClass() == b.getClass() ) {
            final BiPredicate<Object,Object> ruleA = equalityRules.get( a.getClass() );
            return ruleA == null ? defaultEqualityRule : ruleA;
        }
        final BiPredicate<Object,Object> ruleA = equalityRules.get( a.getClass() );
        final BiPredicate<Object,Object> ruleB = equalityRules.get( b.getClass() );
        if ( ruleA == ruleB ) {
            return ruleA == null ? defaultEqualityRule : ruleA;
        }
        if ( a.getClass().isAssignableFrom( b.getClass() ) ||
            b.getClass().isAssignableFrom( (a.getClass()) ) )
        {
            // one is a subclass of the other
            throw new RuntimeException( "Attempting equality check between objects of classes " +
                " " + a.getClass().getName() + " and " + b.getClass().getName() + " where one class is " +
                "a subclass of the other - you need to explicitly an equality set (SAME INSTANCE FOR BOTH) for both classes" );
        }
        return ALWAYS_FALSE;
    }

    /**
     * Adds a custom rule for performing equality comparison on a given type.
     *
     * <p>If no custom rules have been configured or none matches, {@link Object#equals will be used}.</p>
     * @param clazz type this equality rule should be used for
     * @param rule the rule
     * @see #setDefaultEqualityRule(BiPredicate)
     */
    public void addEqualityRule(Class<?> clazz, BiPredicate<Object,Object> rule) {
        Validate.notNull( clazz, "clazz must not be null" );
        Validate.notNull( rule, "rule must not be null" );
        Validate.isTrue( !equalityRules.containsKey( clazz ), "There already is an equality rule configured for class " + clazz + ": "+
            equalityRules.get( clazz ) );
        equalityRules.put( clazz, rule );
    }

    /**
     * Sets the {@link BiPredicate<Object,Object> equality rule} to use when comparing a newly generated field value
     * against the field's current value.
     *
     * @param equalityRule rule to use
     */
    public void setDefaultEqualityRule(BiPredicate<Object,Object> equalityRule)
    {
        Validate.notNull( equalityRule, "equalityRule must not be null" );
        this.defaultEqualityRule = equalityRule;
    }
}
