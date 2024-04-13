package de.codesourcery.littlefuzz;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
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
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.random.RandomGenerator;
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

    /** Default set of characters to use when generating random strings */
    public static final char[] CHARS = "abcdefghijklmnopqrstuvwxyz0123456789".toCharArray();

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
    public interface IFieldResolver
    {
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
        /**
         * Generate a new field value.
         *
         * @param context context information
         * @return new field value to assign
         * @throws IllegalAccessException may be thrown if implementation tries to access the current field and fails.
         */
        Object getValue(IContext context) throws IllegalAccessException;

        /**
         * Wraps an {@link IValueSupplier} so that it never returns the value the current field already has.
         *
         * This method relies on the {@link IEqualityRule equality rule} configured on the current fuzzer.
         *
         * @param other
         * @param attempts how often to attempt generating a different value before giving up and throwing a <code>RuntimeException</code>.
         * @return wrapped value supplier
         * @see IEqualityRule
         * @see Fuzzer#setDefaultEqualityRule(IEqualityRule)
         * @see Fuzzer#addEqualityRule(Class, IEqualityRule)
         * @see IContext#getEqualityRule(Object, Object)
         */
        static IValueSupplier differentValue(IValueSupplier other, int attempts) {
            return context -> {
                final Object currentValue = context.getFieldValue();
                int retries = attempts;
                while( retries-- > 0 ) {
                    final Object newValue = other.getValue( context );
                    if ( ! context.getEqualityRule( currentValue, newValue ).equals( currentValue, newValue ) ) {
                        return newValue;
                    }
                }
                throw new RuntimeException( "Bailing out after failing to come up with a different value for " + currentValue + " for" +
                    " " + attempts + " times." );
            };
        }
    }

    /**
     * Provides access to information about the member field that
     * is currently being fuzzed.
     *
     * @author tobias.gierke@code-sourcery.
     */
    public interface IContext
    {
        /**
         * Returns the {@link IEqualityRule equality rule} to use for two given values.
         *
         * @param a value A
         * @param b value B
         * @return the rule to use
         * @throws RuntimeException when one object is a subclass of the other and no
         *                          suitable equality rule has been {@link #addEqualityRule(Class, IEqualityRule) registered}.
         * @see #addEqualityRule(Class, IEqualityRule)
         * @see #setDefaultEqualityRule(IEqualityRule)
         */
        IEqualityRule getEqualityRule(Object a, Object b);

        /**
         * Returns the random generator to use.
         * @return random generator
         */
        RandomGenerator getRandomGenerator();

        /**
         * Returns the field that is currently being fuzzed.
         *
         * @return field
         */
        Field getField();

        /**
         * Returns the fuzzer instance.
         * @return
         */
        Fuzzer getFuzzer();

        /**
         * Returns the value of the current field
         * @return field value, may be <code>null</code>
         * @throws IllegalAccessException if the field is inaccessible
         * @see #getField()
         */
        Object getFieldValue() throws IllegalAccessException;
    }

    /**
     * Generates a new value for given field and applies it (if desired/applicable
     *
     * @author tobias.gierke@code-sourcery.de
     */
    @FunctionalInterface
    public interface IFuzzingRule {

        /**
         * A no-op rule that does nothing.
         */
        IFuzzingRule NOP_RULE = (fieldInfo, setter) -> {};

        /**
         * Creates a rule that assigns a value from a supplier.
         *
         * @param supplier provides the value to assign
         * @return the rule using that supplier
         * @see #fromSupplier(IValueSupplier)
         */
        static IFuzzingRule fromSupplier(Supplier<?> supplier) {
            return (context, setter) -> setter.set( supplier.get() );
        }

        /**
         * Creates a rule that assigns a value from a {@link IValueSupplier}.
         *
         * @param supplier provides the value to assign
         * @return the rule using that supplier
         * @see #fromSupplier(Supplier)
         */
        static IFuzzingRule fromSupplier(IValueSupplier supplier) {
            return (context, setter) -> setter.set( supplier.getValue(context) );
        }

        /*
         * Fuzz a given field.
         *
         * @param context information about field that should be assigned etc.
         * @param setter setter that should be used to assign the field a new value
         * @throws IllegalAccessException reflection...
         */
        void fuzz(IContext context, IFieldSetter setter) throws IllegalAccessException;
    }

    @FunctionalInterface
    public interface IFieldSetter {
        void set(Object value) throws IllegalAccessException;
    }

    private final RandomGenerator randomGenerator;

    private IEqualityRule defaultEqualityRule = Objects::equals;

    // rules how to generate values of a given type.
    // the type is the map key while the generation rule is the value
    private final Map<Class<?>, IFuzzingRule> typeRules = new HashMap<>();

    // rules how to generate values for a field of a specific class
    // the type is the FieldMatch key while the generation rule is the value
    private final Map<FieldMatch, IFuzzingRule> fieldRules = new HashMap<>();

    // Rules describing how to compare values of a specific type.
    private final Map<Class<?>, IEqualityRule> equalityRules = new HashMap<>();

    private final Map<Class<?>, IFieldResolver> fieldResolvers = new HashMap<>();

    private IFieldResolver defaultFieldResolver = (clazz, includingInheritedFields) -> {
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
     * Creates a new instance with a {@link java.util.Random} seeded  using {@link System#nanoTime()}.
     * @see Fuzzer(long)
     */
    public Fuzzer() {
        this( System.nanoTime() );
    }

    /**
     * Creates a new instance with the random seed set
     * using {@link System#nanoTime()}.
     */
    public Fuzzer(long seed) {
        this( new Random( seed ) );
    }

    /**
     * Creates a new instance with a given random generator.
     *
     * @param random random generator to use
     */
    public Fuzzer(RandomGenerator random) {
        Validate.notNull( random, "random must not be null" );
        this.randomGenerator = random;
    }

    /**
     * Clears all field- and type-based fuzzing rules.
     * @see #clearFieldRules()
     * @see #clearTypeRules()
     */
    public void clearRules() {
        clearFieldRules();
        clearTypeRules();
    }

    /**
     * Clears all field-based fuzzing rules.
     * @see #clearTypeRules()
     * @see #clearRules()
     */
    public void clearFieldRules() {
        this.fieldRules.clear();
    }

    /**
     * Clears all type-based fuzzing rules.
     * @see #clearTypeRules()
     * @see #clearRules()
     */
    public void clearTypeRules() {
        this.typeRules.clear();
    }

    /**
     * Clears all field and type rules and sets up default rules for JDK built-in datatypes.
     *
     * @param wrapperGenerator optional function to wrap the default suppliers before registering
     *                         them. May be <code>null</code> to not perform any wrapping at all.
     * @see #clearRules()
     */
    public void setupDefaultRules(Function<Supplier<?>,IValueSupplier> wrapperGenerator) {

        clearRules();

        if ( wrapperGenerator == null ) {
            wrapperGenerator = (toWrap) -> (ctx) -> toWrap.get();
        }

        addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( () ->  {
            final byte[] array = new byte[16];
            randomGenerator.nextBytes( array );
            return new BigInteger( array ).toString( 16 );
        } ) ), String.class);

        addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( randomGenerator::nextLong ) ), Long.class, Long.TYPE);
        addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( randomGenerator::nextInt ) ), Integer.class, Integer.TYPE);
        addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( () -> (short) randomGenerator.nextInt() ) ), Short.class, Short.TYPE);
        addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( randomGenerator::nextFloat ) ), Float.class, Float.TYPE);
        addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( randomGenerator::nextDouble ) ), Double.class, Double.TYPE);
        addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( () -> (byte) randomGenerator.nextInt() ) ), Byte.class, Byte.TYPE);
        addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( randomGenerator::nextBoolean ) ), Boolean.class, Boolean.TYPE);
        addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( () -> java.time.Instant.ofEpochMilli( randomGenerator.nextLong() ).atZone( ZoneId.systemDefault() ) ) ), ZonedDateTime.class  );
    }

    private IEqualityRule getEqualityRule(Object a, Object b)
    {
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
                    final int idx = randomGenerator.nextInt( 0, list.size() );
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
                        if ( randomGenerator.nextBoolean() )
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
                final int idx = randomGenerator.nextInt( 0, list.size() );
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
                    if ( randomGenerator.nextBoolean() && ! alreadyPicked.contains( idx ) )
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
        final int size = randomGenerator.nextInt( 1, 30 );
        final Map<String, String> map = new HashMap<>();
        for ( int i = 0 ; i < size ; i++ ) {
            final String key = createRandomString( minKeyLen, maxKeyLen );
            final String value = createRandomString( minValueLen, maxValueLen );
            map.put( key, value );
        }
        return map;
    }

    /**
     * Creates a random string with a random length.
     * @param minLen minimum length the string should have (inclusive)
     * @param maxLen maximum length the string should have (inclusive)
     * @return random string
     */
    public String createRandomString(int minLen, int maxLen) {
        return createRandomString( minLen, maxLen, CHARS );
    }
    /**
     * Creates a random string with a random length.
     * @param minLen minimum length the string should have (inclusive)
     * @param maxLen maximum length the string should have (inclusive)
     * @param chars set of characters to create random string from.
     * @return random string
     */
    public String createRandomString(int minLen, int maxLen, char[] chars) {
        Validate.isTrue( minLen >= 0 );
        Validate.isTrue( maxLen >= minLen );
        Validate.isTrue( chars != null && chars.length > 0 , "need at least one character to choose from");

        final int len = minLen == maxLen ? minLen : minLen + randomGenerator.nextInt( maxLen - minLen -1 );
        final StringBuilder buffer = new StringBuilder();
        for ( int i = len ; i > 0 ; i-- ) {
            buffer.append( CHARS[randomGenerator.nextInt( 0, CHARS.length )] );
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

    private IFieldResolver getFieldResolver(Class<?> clazz) {
        final IFieldResolver result = fieldResolvers.get( clazz );
        return result != null ? result : defaultFieldResolver;
    }

    private static final class FieldInfo implements IContext
    {
        public final Fuzzer fuzzer;
        public final Object object;
        public final RandomGenerator randomGenerator;
        public Field currentField;

        private FieldInfo(Fuzzer fuzzer, Object object, RandomGenerator randomGenerator)
        {
            Validate.notNull( fuzzer, "fuzzer must not be null" );
            Validate.notNull( object, "object must not be null" );
            Validate.notNull( randomGenerator, "randomGenerator must not be null" );
            this.fuzzer = fuzzer;
            this.object = object;
            this.randomGenerator = randomGenerator;
        }

        @Override
        public IEqualityRule getEqualityRule(Object a, Object b)
        {
            return fuzzer.getEqualityRule( a, b );
        }

        @Override
        public RandomGenerator getRandomGenerator()
        {
            return randomGenerator;
        }

        @Override
        public Field getField()
        {
            return currentField;
        }

        @Override
        public Fuzzer getFuzzer()
        {
            return fuzzer;
        }

        @Override
        public Object getFieldValue() throws IllegalAccessException
        {
            return currentField.get(object);
        }
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
        final FieldInfo info = new FieldInfo(this , obj, randomGenerator );
        for ( Field f : getFieldResolver( obj.getClass() ).getFields( obj.getClass(), includingInheritedFields ) )
        {
            info.currentField = f;
            f.setAccessible( true );
            assignRandomValue( f, info, value -> {
                f.set( obj, value );
            } );
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
        final int idx = randomGenerator.nextInt( 0, values.length );
        return Optional.of( values[idx] );
    }

    private void assignRandomValue(Field f, IContext fieldInfo, Fuzzer.IFieldSetter setter) throws IllegalAccessException {
        if ( debug ) {
            System.out.println( "Assigning random value to "+f);
        }
        getRule( f ).fuzz( fieldInfo, setter );
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
     * Sets the implementation to be used when resolving fields in need of fuzzing.
     *
     * @param fieldResolver resolver
     */
    public void setDefaultFieldResolver(IFieldResolver fieldResolver)
    {
        Validate.notNull( fieldResolver, "fieldResolver must not be null" );
        this.defaultFieldResolver = fieldResolver;
    }

    /**
     * Sets the implementation to be used when resolving fields in need of fuzzing.
     *
     * @param fieldResolver resolver
     */
    public void setFieldResolver(IFieldResolver fieldResolver,Class<?> clazz,Class<?>... additional)
    {
        Validate.notNull( fieldResolver, "fieldResolver must not be null" );
        this.defaultFieldResolver = fieldResolver;
    }
}