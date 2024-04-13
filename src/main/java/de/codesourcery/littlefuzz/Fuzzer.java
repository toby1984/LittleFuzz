package de.codesourcery.littlefuzz;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import org.apache.commons.lang3.Validate;

/**
 * Test helper class to assign random values ('fuzz') to instance fields.
 *
 * <p>
 * This fuzzer comes with some default rules for common Java field types like primitives
 * as well as some rules for
 * </p>
 * @author tobias.gierke@code-sourcery.de
 */
public class Fuzzer
{
    private boolean debug;

    private static final Pattern THIS_PTR = Pattern.compile( "^this\\$\\d+$" );

    private static final IEqualityRule ALWAYS_FALSE = (a,b) -> false;

    // fuzzing rule resolvers for a given class.
    // key is the class declaring a given field, resolver is the resolver to
    // use for that given
    private final Map<Class<?>, IRuleResolver> ruleResolvers = new HashMap<>();

    public record FieldMatch(Class<?> clazz, String fieldName) {
        public FieldMatch
        {
            Validate.notNull( clazz, "clazz must not be null" );
            Validate.notBlank( fieldName, "fieldName must not be null or blank");
            if ( Arrays.stream( clazz.getDeclaredFields() ).filter( x -> ! Modifier.isStatic(x.getModifiers()))
                .noneMatch( field -> field.getName().equals( fieldName ) ) ) {
                throw new IllegalArgumentException( "Class '" + clazz.getName() + "' has no non-static field '" + fieldName + "'" );
            }
        }
    }

    /**
     * Returns all {@link Field member fields} for a given class.
     *
     * @author tobias.gierke@code-sourcery.de
     */
    public interface IFieldProvider {

        /**
         *
         * @param clazz the class to get fields for, never
         * @param includeInherited whether to also return fields from super-classes
         * @return list of fields
         */
        List<Field> getFields(Class<?> clazz, boolean includeInherited);
    }

    /**
     * Equality rule.
     * <p>
     * Useful if a class does not come with a suitable {@link Object#equals(Object)} implementation.
     * This rule gets applied when checking whether a newly generated field value is the same as
     * the field's current value.
     * </p>
     *
     * @author tobias.gierke@code-sourcery.de
     * @see #addEqualityRule(Class, IEqualityRule)
     */
    @FunctionalInterface
    public interface IEqualityRule {
        boolean equals(Object a, Object b);
    }

    /**
     * Locates the rule to use for a given field.
     *
     * @author tobias.gierke@code-sourcery.de
     */
    @FunctionalInterface
    public interface IRuleResolver
    {
        IFuzzingRule getRule(Field field);
    }

    /**
     * Provides a new value for a given field.
     *
     * @author tobias.gierke@code-sourcery.de
     */
    @FunctionalInterface
    public interface IValueSupplier {
        Object getValue(Fuzzer fuzzer) throws IllegalAccessException;
    }

    /**
     * Generates a new value for given field and applies it (if desired/applicable
     *
     * @author tobias.gierke@code-sourcery.de
     */
    @FunctionalInterface
    public interface IFuzzingRule {

        /**
         * A rule that does nothing/does not assign a field value.
         */
        IFuzzingRule NOP_RULE = (fuzzer, field, currentValue, setter) -> {};

        static  Object generateValue(Fuzzer fuzzer, Object currentValue, IValueSupplier newValueGenerator) throws IllegalAccessException
        {
            return generateValue( fuzzer, currentValue, newValueGenerator, fuzzer.getMaxNewValueGenerationAttempts() );
        }

        /**
         * Creates a rule that assigns a value using a given value supplier.
         *
         * @param supplier supplies the value for the rule
         * @return rule
         */
        static IFuzzingRule withSupplier(Supplier<?> supplier) {
            return withSupplier( fuzzer -> supplier.get() );
        }

        /**
         * Creates a rule that unconditionally assigns a value without doing any equality checks against the current field value.
         * @param supplier provides the value to assign
         * @return rule the rule
         */
        static IFuzzingRule withSupplierNoChecks(Supplier<?> supplier) {
            return (fuzzer, field, currentValue, setter) -> setter.set( supplier.get() );
        }

        /**
         * Creates a rule that assigns a value using a given value supplier.
         *
         * @param supplier supplier
         * @return rule
         */
        static IFuzzingRule withSupplier(IValueSupplier supplier) {
            return (fuzzer, field, currentValue, setter) -> setter.set( IFuzzingRule.generateValue( fuzzer, currentValue, supplier ) );
        }

        static Object generateValue(Fuzzer fuzzer, Object currentValue, IValueSupplier newValueGenerator, int attempts) throws IllegalAccessException
        {
            int retries = attempts;
            while( retries-- > 0 ) {
                final Object newValue = newValueGenerator.getValue( fuzzer );
                if ( ! fuzzer.getEqualityRule( currentValue, newValue ).equals( currentValue, newValue ) ) {
                    return newValue;
                }
            }
            throw new RuntimeException( "Bailing out after failing to come up with a different value for " + currentValue + " for" +
                " " + attempts + " times." );
        }

        /**
         * Fuzz a given field.
         *
         * @param fuzzer fuzzer
         * @param field field to assign new value to
         * @param currentValue current field value
         * @param setter setter that should be used to assign the field a new value
         * @throws IllegalAccessException reflection...
         */
        void fuzz(Fuzzer fuzzer, Field field, Object currentValue, IFieldSetter setter) throws IllegalAccessException;
    }

    @FunctionalInterface
    public interface IFieldSetter {
        void set(Object value) throws IllegalAccessException;
    }

    public final Random rnd;
    private int maxNewValueGenerationAttempts = 10;

    private IEqualityRule defaultEqualityRule = Objects::equals;

    // rules how to generate values of a given type.
    // the type is the map key while the generation rule is the value
    private final Map<Class<?>, IFuzzingRule> typeRules = new HashMap<>();

    // rules how to generate values for a field of a specific class
    // the type is the FieldMatch key while the generation rule is the value
    private final Map<FieldMatch, IFuzzingRule> fieldRules = new HashMap<>();

    // Rules describing how to compare values of a specific type.
    private final Map<Class<?>, IEqualityRule> equalityRules = new HashMap<>();

    private IFieldProvider fieldProvider = (clazz, includingInheritedFields) -> {
        final List<Field> fields = new ArrayList<>();

        final Predicate<Field> isSuitableField = (field) -> {
            if ( ! Modifier.isStatic( field.getModifiers() ) ) {
                // ignore pointer to enclosing class
                return ! THIS_PTR.matcher( field.getName() ).matches();
            }
            return false;
        };

        if ( includingInheritedFields )
        {
            Class<?> current = clazz;
            while (current != Object.class)
            {
                for ( final Field f : current.getDeclaredFields() )
                {
                    if ( isSuitableField.test( f ) )
                    {
                        fields.add( f );
                    }
                }
                current = current.getSuperclass();
            }
        } else {
            for ( final Field field : clazz.getDeclaredFields() )
            {
                if ( isSuitableField.test(field) ) {
                    fields.add( field );
                }
            }
        }
        return fields;
    };

    private final IRuleResolver defaultRuleResolver = field -> {
        IFuzzingRule result = fieldRules.get( new FieldMatch(field.getDeclaringClass(), field.getName() ) );
        if ( result == null ) {
            result = typeRules.get( field.getType() );
            if ( result == null )
            {
                throw new RuntimeException( "Error, found no fuzzing rule for " + field );
            }
        }
        return result;
    };

    private IFuzzingRule getRule(Field f) {
        return getRuleResolver( f ).getRule( f );
    }

    private IRuleResolver getRuleResolver(Field field) {
        final IRuleResolver resolver = ruleResolvers.get( field.getDeclaringClass() );
        return resolver == null ? defaultRuleResolver : resolver;
    }

    /**
     * Creates a new instance with the random seed set
     * using {@link System#nanoTime()}.
     */
    public Fuzzer() {
        this( System.nanoTime() );
    }

    /**
     * Creates a new instance with a given random seed.
     *
     * @param seed random seed
     */
    public Fuzzer(long seed) {
        rnd = new Random( seed );
        setupDefaultRules();
    }

    /**
     * Sets the random seed used by this fuzzer.
     *
     * @param seed random seed
     */
    public void setSeed(long seed) {
        rnd.setSeed( seed );
    }

    protected void setupDefaultRules() {

        addTypeRule( IFuzzingRule.withSupplier( () ->  {
            final byte[] array = new byte[16];
            rnd.nextBytes( array );
            return new BigInteger( array ).toString( 16 );
        } ), String.class);

        addTypeRule( IFuzzingRule.withSupplier( () -> rnd.nextLong() ), Long.class, Long.TYPE);
        addTypeRule( IFuzzingRule.withSupplier( () -> rnd.nextInt() ), Integer.class, Integer.TYPE);
        addTypeRule( IFuzzingRule.withSupplier( () -> (short) rnd.nextInt() ), Short.class, Short.TYPE);
        addTypeRule( IFuzzingRule.withSupplier( () -> rnd.nextFloat() ), Float.class, Float.TYPE);
        addTypeRule( IFuzzingRule.withSupplier( () -> rnd.nextDouble() ), Double.class, Double.TYPE);
        addTypeRule( IFuzzingRule.withSupplier( () -> (byte) rnd.nextInt() ), Byte.class, Byte.TYPE);
        addTypeRule( IFuzzingRule.withSupplier( rnd::nextBoolean ), Boolean.class, Boolean.TYPE);
        addTypeRule( IFuzzingRule.withSupplier( () -> java.time.Instant.ofEpochMilli( rnd.nextLong() ).atZone( ZoneId.systemDefault() ) ), ZonedDateTime.class  );
    }

    private IEqualityRule getEqualityRule(Object a, Object b) {
        if ( a == null || b == null ) {
            return ALWAYS_FALSE;
        }
        if ( a.getClass() == b.getClass() ) {
            final IEqualityRule ruleA = equalityRules.get( a.getClass() );
            return ruleA == null ? defaultEqualityRule : ruleA;
        }
        final IEqualityRule ruleA = equalityRules.get( a.getClass() );
        final IEqualityRule ruleB = equalityRules.get( b.getClass() );
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
     * @param clazz type this equality rule should be used for
     * @param rule the rule
     */
    public void addEqualityRule(Class<?> clazz, IEqualityRule rule) {
        Validate.notNull( clazz, "clazz must not be null" );
        Validate.notNull( rule, "rule must not be null" );
        Validate.isTrue( !equalityRules.containsKey( clazz ), "There already is an equality rule configured for class " + clazz + ": "+
            equalityRules.get( clazz ) );
        equalityRules.put( clazz, rule );
    }

    /**
     * Adds a rule how to generate new values with a given type.
     *
     * <p>
     * Only one rule can exist for any given class. Use {@link #setTypeRule(IFuzzingRule, Class)}
     * if you want to override an already existing rule.
     * </p>
     * @param rule rule used to generate new values of the given type
     * @param c1 type that is compatible with the values generated by the rule
     * @throws IllegalArgumentException if any of the input parameters are <code>null</code>
     *                                  or a rule has already been registered for the given class.
     *
     * @see #setTypeRule(IFuzzingRule, Class)
     */
    public void addTypeRule(IFuzzingRule rule, Class<?> c1) {
        Validate.notNull( rule, "rule must not be null" );
        Validate.notNull( c1, "c1 must not be null" );
        Validate.isTrue( !typeRules.containsKey( c1 ), "There is already a type rule registered for class " + c1 + ": " + typeRules.get( c1 ) );
        typeRules.put( c1, rule );
    }

    /**
     * Sets the rule how to generate new values with a given type.
     *
     * <p> Only one rule can exist for any given class. </p>
     *
     * @param rule rule used to generate new values of the given type
     * @param c1 type that is compatible with the values generated by the rule
     * @throws IllegalArgumentException if any of the input parameters are <code>null</code>
     */
    public void setTypeRule(IFuzzingRule rule, Class<?> c1) {
        Validate.notNull( rule, "rule must not be null" );
        Validate.notNull( c1, "c1 must not be null" );
        typeRules.put( c1, rule );
    }

    /**
     * Adds a rule how to generate for a specific member field of a given class.
     *
     * @param owningClass class declaring the member field that should be randomized
     * @param fieldName name of the member field
     * @param rule rule used to generate new values for the given member field
     */
    public void addFieldRule(Class<?> owningClass, String fieldName, IFuzzingRule rule) {
        Validate.notNull( rule, "rule must not be null" );
        final FieldMatch key = new FieldMatch( owningClass, fieldName );
        Validate.isTrue( !fieldRules.containsKey( key ), "There is already a rule registered for " + key + ": " + fieldRules.get( key ) );
        fieldRules.put( key, rule );
    }

    /**
     * Adds a rule how to generate new values with a given type.
     *
     * @param rule rule used to generate new values of the given type
     * @param c1 types that are compatible with the values generated by the rule
     */
    public void addTypeRule(IFuzzingRule rule, Class<?> c1, Class<?>... additional) {
        Validate.notNull( rule, "rule must not be null" );
        Validate.notNull( c1, "c1 must not be null" );

        addTypeRule( rule, c1 );
        typeRules.put( c1, rule );
        Arrays.stream( additional ).forEach( x -> addTypeRule( rule, x ) );
    }

    /**
     * Randomly picks a certain number of distinct elements from a given collection.
     *
     * @param collection collection to pick elements from
     * @param noElementsToPick number of elements to pick
     * @param repetitionAllowed whether the same element may be picked more than once
     * @return a list containing the selected elements
     * @param <T> collection type
     */
    public <T> List<T> pickRandomElements(Collection<T> collection, int noElementsToPick, boolean repetitionAllowed) {

        noElementsToPick = Math.min( collection.size(), noElementsToPick );
        if ( noElementsToPick == 0 ) {
            return new ArrayList<>(0);
        }

        final List<T> result = new ArrayList<>(noElementsToPick);
        if ( repetitionAllowed ) {

            if ( collection instanceof List<T> list) {
                while (result.size() < noElementsToPick)
                {
                    final int idx = rnd.nextInt( 0, list.size() );
                    result.add( list.get( idx ) );
                }
            }
            else {
                while (result.size() < noElementsToPick)
                {
                    final Iterator<T> it = collection.iterator();
                    while (it.hasNext() && result.size() < noElementsToPick)
                    {
                        final T obj = it.next();
                        if ( rnd.nextBoolean() )
                        {
                            result.add( obj );
                        }
                    }
                }
            }
            return result;
        }
        final Set<Integer> alreadyPicked = new HashSet<>();

        if ( collection instanceof List<T> list) {
            while (result.size() < noElementsToPick)
            {
                final int idx = rnd.nextInt( 0, list.size() );
                if ( ! alreadyPicked.contains( idx ) )
                {
                    alreadyPicked.add( idx );
                    result.add( list.get( idx ) );
                }
            }
        }
        else
        {
            while (result.size() < noElementsToPick)
            {
                final Iterator<T> it = collection.iterator();
                int idx = 0;
                while (it.hasNext() && result.size() < noElementsToPick)
                {
                    final T obj = it.next();
                    if ( rnd.nextBoolean() && ! alreadyPicked.contains( idx ) )
                    {
                        alreadyPicked.add( idx );
                        result.add( obj );
                    }
                    idx++;
                }
            }
        }
        return result;
    }

    /**
     * Creates a map with random strings.
     *
     * @param minKeyLen min. length of map keys
     * @param maxKeyLen max. length of map keys
     * @param minValueLen min. length of map values
     * @param maxValueLen max. length of map values
     * @return random map
     */
    public Map<String,String> createRandomStringMap(int minKeyLen, int maxKeyLen, int minValueLen, int maxValueLen) {
        final int size = rnd.nextInt( 1, 30 );
        final Map<String, String> map = new HashMap<>();
        for ( int i = 0 ; i < size ; i++ ) {
            final String key = createRandomString( minKeyLen, maxKeyLen );
            final String value = createRandomString( minValueLen, maxValueLen );
            map.put( key, value );
        }
        return map;
    }

    private static final char[] CHARS = "abcdefghijklmnopqrstuvwxyz0123456789".toCharArray();

    /**
     * Creates a random string with a random length.
     * @param minLen minimum length the string should have (inclusive)
     * @param maxLen maximum length the string should have (inclusive)
     * @return random string
     */
    public String createRandomString(int minLen, int maxLen) {
        Validate.isTrue( minLen >= 0 );
        Validate.isTrue( maxLen >= minLen );

        final int len = minLen == maxLen ? minLen : minLen + rnd.nextInt( maxLen - minLen -1 );
        final StringBuilder buffer = new StringBuilder();
        for ( int i = len ; i > 0 ; i-- ) {
            buffer.append( CHARS[rnd.nextInt( 0, CHARS.length )] );
        }
        return buffer.toString();
    }

    /**
     * Assigns random values to all declared or inherited non-static member fields of an object.
     *
     * @param obj object whose fields should have random values assigned
     * @return object instance (for chaining)
     * @param <T> evidence to avoid cast warnings
     * @throws IllegalAccessException when assigning a non-static member field went wrong
     */
    public <T> T assignRandomValues(T obj) throws IllegalAccessException
    {
        return assignRandomValues( obj, true );
    }

    /**
     * Assigns random values to the fields of an object.
     *
     * @param obj object whose fields should have random values assigned
     * @param includingInheritedFields whether to also assign fields inherited from any superclass
     * @return object instance (for chaining)
     * @param <T> evidence to avoid cast warnings
     * @throws IllegalAccessException when assigning a non-static member field went wrong
     */
    public <T> T assignRandomValues(T obj, boolean includingInheritedFields) throws IllegalAccessException
    {
        Validate.notNull( obj, "obj must not be null" );
        if ( debug ) {
            System.out.println( "Randomizing object " + obj.getClass().getName() );
        }
        for ( Field f : fieldProvider.getFields( obj.getClass(), includingInheritedFields ) )
        {
            f.setAccessible( true );
            assignRandomValue( f, f.get( obj ), v -> f.set(obj, v ) );
        }
        return obj;
    }

    /**
     * Picks a random value from an enumeration.
     *
     * @param enumClass enum to pick values from
     * @return random value or <code>Optional.empty()</code> if the enumeration has no values at all
     */
    public Optional<Object> pickRandomEnumValue(Class<?> enumClass) {
        Validate.notNull( enumClass, "enumClass must not be null" );
        Validate.isTrue( enumClass.isEnum(), "Not an enum class: "+enumClass);

        final Object[] values = enumClass.getEnumConstants();
        if ( values.length == 0 ) {
            return Optional.empty();
        }
        final int idx = rnd.nextInt( 0, values.length );
        return Optional.of( values[idx] );
    }

    /**
     * Returns how many attempts this fuzzer will make at generating a new field
     * value before giving up.
     *
     * @return max. number of attempts
     * @see #setMaxNewValueGenerationAttempts(int)
     */
    public int getMaxNewValueGenerationAttempts()
    {
        return maxNewValueGenerationAttempts;
    }

    /**
     * Sets how often to attempt generating a new field value that is different from
     * the existing field's existing value before failing.
     *
     * <p>
     * This method exists to avoid the fuzzer getting stuck on generator functions
     * that fail to come up with a different value.
     * </p>
     *
     * @param maxNewValueGenerationAttempts max. number of attempts, must be greater than zero.
     * @return this instance (for chaining)
     */
    public Fuzzer setMaxNewValueGenerationAttempts(int maxNewValueGenerationAttempts)
    {
        Validate.isTrue( maxNewValueGenerationAttempts > 0 );
        this.maxNewValueGenerationAttempts = maxNewValueGenerationAttempts;
        return this;
    }

    /**
     * Fuzz a member field value.
     *
     * @param f member field to fuzz value for
     * @param currentValue the field's current value
     * @param setter callback used to assign the field value
     * @throws IllegalAccessException may be thrown by setter callback
     */
    public void assignRandomValue(Field f, Object currentValue, Fuzzer.IFieldSetter setter) throws IllegalAccessException {
        if ( debug ) {
            System.out.println( "Assigning random value to "+f);
        }
        getRule( f ).fuzz( this, f, currentValue, setter );
    }

    /**
     * Sets the rule resolver to use when randomizing the fields on a specific class.
     *
     * <p>If no specific resolver has been configured for a class, a generic default resolver is being used instead.</p>
     *
     * @param ruleResolver rule resolver
     * @param clazz class for whose fields this resolver should be used
     */
    public void addRuleResolver(IRuleResolver ruleResolver, Class<?> clazz) {
        Validate.notNull( ruleResolver, "ruleResolver must not be null" );
        Validate.notNull( clazz, "clazz must not be null" );
        Validate.isTrue( !ruleResolvers.containsKey( clazz ), "There is already a rule resolver registered for " + clazz + ": " +
            ruleResolvers.get( clazz ) );
        ruleResolvers.put( clazz, ruleResolver );
    }

    /**
     * Turn on verbose logging to help with configuring this fuzzer.
     *
     * @param debug enable/disable debug output
     * @return this instance (for chaining)
     */
    public Fuzzer setDebug(boolean debug)
    {
        this.debug = debug;
        return this;
    }

    /**
     * Set default {@link IEqualityRule equality rule} to use when comparing a newly generated field value against
     * the field's current value.
     *
     * @param defaultEqualityRule rule to use
     * @return this instance (for chaining)
     */
    public Fuzzer setDefaultEqualityRule(IEqualityRule defaultEqualityRule)
    {
        Validate.notNull( defaultEqualityRule, "defaultEqualityRule must not be null" );
        this.defaultEqualityRule = defaultEqualityRule;
        return this;
    }

    /**
     * Sets the implementation that should be used to resolve fields in need of fuzzing
     * @param fieldProvider
     */
    public void setFieldProvider(IFieldProvider fieldProvider)
    {
        Validate.notNull( fieldProvider, "fieldProvider must not be null" );
        this.fieldProvider = fieldProvider;
    }
}