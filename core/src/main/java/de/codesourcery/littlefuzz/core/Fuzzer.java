/*
 * Copyright © 2024 Tobias Gierke (tobias.gierke@code-sourcery.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.codesourcery.littlefuzz.core;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang3.Validate;

/**
 * Test helper class to assign random values ('fuzz') to object properties.
 *
 * <p>By default, this class is initialized with a {@link FieldResolver} so will
 * only inject values into member fields.</p>
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class Fuzzer
{
    private boolean debug;

    private record PropertyMatch(Class<?> clazz, String propertyName) {
        public PropertyMatch
        {
            Validate.notNull( clazz, "clazz must not be null" );
            Validate.notBlank( propertyName, "propertyName must not be null or blank");
        }

        public boolean matches(IProperty property) {
            return property.getDeclaringClass() == clazz && property.getName().equals( propertyName );
        }
    }

    /**
     * Default rule resolver that relies on {@link #addTypeRule(IFuzzingRule, Class) property type rules} and
     * {@link #addPropertyRule(Class, String, IFuzzingRule) declaring class as well as property name}.
     */
    public static final IRuleResolver DEFAULT_RULE_RESOLVER = (ctx) -> {
        final Fuzzer fuzzer = ctx.getFuzzer();
        final IProperty property = ctx.getProperty();
        IFuzzingRule result = fuzzer.propertyRules.get( new PropertyMatch( property.getDeclaringClass(), property.getName() ) );
        if ( result == null ) {
            result = fuzzer.typeRules.get( property.getType() );
        }
        return result;
    };

    /**
     * Default resolver to use, currently a {@link FieldResolver}.
     */
    public static final IPropertyResolver DEFAULT_RESOLVER = CachingPropertyResolver.wrap( new FieldResolver() );

    /**
     * Provides access to information about the property that is currently being fuzzed.
     *
     * @author tobias.gierke@code-sourcery.
     */
    public interface IContext
    {
        /**
         * Returns the property that is currently being fuzzed.
         *
         * @return property
         */
        IProperty getProperty();

        /**
         * Returns the fuzzer instance.
         *
         * @return fuzzer
         */
        Fuzzer getFuzzer();

        /**
         * Returns the value of the current property.
         *
         * @return property value, may be <code>null</code>
         * @see #getProperty()
         */
        Object getPropertyValue();

        boolean includeInherited();
    }

    private static final class Context implements IContext
    {
        public final Fuzzer fuzzer;
        public final Object target;
        public final boolean includeInherited;
        public IProperty currentProperty;

        private Context(Fuzzer fuzzer, Object target, boolean includeInherited)
        {
            Validate.notNull( fuzzer, "fuzzer must not be null" );
            Validate.notNull( target, "target object must not be null" );
            this.fuzzer = fuzzer;
            this.target = target;
            this.includeInherited = includeInherited;
        }

        @Override
        public IProperty getProperty()
        {
            return currentProperty;
        }

        @Override
        public Fuzzer getFuzzer()
        {
            return fuzzer;
        }

        @Override
        public Object getPropertyValue()
        {
            return currentProperty.getValue( target );
        }

        @Override
        public boolean includeInherited()
        {
            return includeInherited;
        }

    }

    // rules how to generate values of a given type.
    // the type is the map key while the generation rule is the value
    private final Map<Class<?>, IFuzzingRule> typeRules = new HashMap<>();

    // rules how to generate values for a property of a specific class
    private final Map<PropertyMatch, IFuzzingRule> propertyRules = new HashMap<>();

    private IPropertyResolver propertyResolver = DEFAULT_RESOLVER;

    private IRuleResolver ruleResolver = DEFAULT_RULE_RESOLVER;

    /**
     * Creates a new instance with a {@link java.util.Random} seeded  using {@link System#nanoTime()}.
     * @see Fuzzer(long)
     */
    public Fuzzer() {
    }

    /**
     * Clears all property- and type-based fuzzing rules.
     *
     * @return this instance (for chaining)
     * @see #clearPropertyRules()
     * @see #clearTypeRules()
     */
    public Fuzzer clearRules() {
        clearPropertyRules();
        clearTypeRules();
        return this;
    }

    /**
     * Clears all property-based fuzzing rules.
     *
     * @return this instance (for chaining)
     * @see #clearTypeRules()
     * @see #clearRules()
     */
    public Fuzzer clearPropertyRules() {
        this.propertyRules.clear();
        return this;
    }

    /**
     * Clears all type-based fuzzing rules.
     *
     * @return this instance (for chaining)
     * @see #clearTypeRules()
     * @see #clearRules()
     */
    public Fuzzer clearTypeRules() {
        this.typeRules.clear();
        return this;
    }

    /**
     * Adds a rule how to generate new values with a given type.
     *
     * <p>
     * Only one rule can exist for any given class. Use {@link #setTypeRule(IFuzzingRule, Class)}
     * if you want to override an already existing rule.
     * </p>
     *
     * @param rule rule used to generate new values of the given type
     * @param c1   type that is compatible with the values generated by the rule
     * @return this instance (for chaining)
     * @throws IllegalArgumentException if any of the input parameters are <code>null</code>
     *                                  or a rule has already been registered for the given class.
     * @see #setTypeRule(IFuzzingRule, Class)
     */
    public Fuzzer addTypeRule(IFuzzingRule rule, Class<?> c1) {
        Validate.notNull( rule, "rule must not be null" );
        Validate.notNull( c1, "c1 must not be null" );
        Validate.isTrue( !typeRules.containsKey( c1 ), "There is already a type rule registered for class " + c1 + ": " + typeRules.get( c1 ) );
        typeRules.put( c1, rule );
        return this;
    }

    /**
     * Sets the rule how to generate new values with a given type.
     *
     * <p> Only one rule can exist for any given class. </p>
     *
     * @param rule rule used to generate new values of the given type
     * @param c1   type that is compatible with the values generated by the rule
     * @return this instance (for chaining)
     * @throws IllegalArgumentException if any of the input parameters are <code>null</code>
     */
    public Fuzzer setTypeRule(IFuzzingRule rule, Class<?> c1) {
        Validate.notNull( rule, "rule must not be null" );
        Validate.notNull( c1, "c1 must not be null" );
        typeRules.put( c1, rule );
        return this;
    }

    /**
     * Adds a rule how to generate for a specific property of a given class.
     *
     * @param owningClass class declaring the property
     * @param propertyName name of the property to assign
     * @param rule rule used to generate new values
     * @return this instance (for chaining)
     * 
     * @throws IllegalArgumentException if the owning class does not have a property by that name or 
     *                                  if another rule was already registered for this class and property name.
     *                                  
     * @see #setPropertyRule(Class, String, IFuzzingRule) 
     */
    public Fuzzer addPropertyRule(Class<?> owningClass, String propertyName, IFuzzingRule rule) {
        Validate.notNull( rule, "rule must not be null" );
        final PropertyMatch key = new PropertyMatch( owningClass, propertyName );
        Validate.isTrue( !propertyRules.containsKey( key ), "There is already a rule registered for " + key + ": " + propertyRules.get( key ) );
        return setPropertyRule( owningClass, propertyName, rule );
    }

    /**
     * Assigns a rule how to generate for a specific property of a given class.
     * 
     * <p>Unlike {@link #addPropertyRule(Class, String, IFuzzingRule)} , this method
     * will not fail if another rule has already been configured for the property.</p>
     *
     * @param owningClass class declaring the property
     * @param propertyName name of the property to assign
     * @param rule rule used to generate new values
     * @return this instance (for chaining)
     *
     * @throws IllegalArgumentException if the owning class does not have a property by that name or 
     *                                  if another rule was already registered for this class and property name.      
     * @see #addPropertyRule(Class, String, IFuzzingRule) 
     */
    public Fuzzer setPropertyRule(Class<?> owningClass, String propertyName, IFuzzingRule rule) {
        Validate.notNull( rule, "rule must not be null" );
        final PropertyMatch key = new PropertyMatch( owningClass, propertyName );

        if ( propertyResolver.getProperties( owningClass, false ).stream().noneMatch( key::matches ) &&
            propertyResolver.getProperties( owningClass, true  ).stream().noneMatch( key::matches ) ) {
            throw new IllegalArgumentException("Property resolver did not return any property named '"+propertyName+"'" +
                " in class '"+owningClass.getName()+"'");
        }
        propertyRules.put( key, rule );
        return this;
    }    
    
    /**
     * Adds a rule how to generate new values with a given type.
     *
     * @param rule rule used to generate new values of the given type
     * @param c1   types that are compatible with the values generated by the rule
     * @return this instance (for chaining)
     */
    @SuppressWarnings("UnusedReturnValue")
    public Fuzzer addTypeRule(IFuzzingRule rule, Class<?> c1, Class<?>... additional) {
        Validate.notNull( rule, "rule must not be null" );
        Validate.notNull( c1, "c1 must not be null" );

        addTypeRule( rule, c1 );
        typeRules.put( c1, rule );
        Arrays.stream( additional ).forEach( x -> addTypeRule( rule, x ) );
        return this;
    }

    /**
     * Apply fuzzing rules to an object.
     *
     * <p><b>This method will tell the current {@link IPropertyResolver} to also consider
     * inherited properties.</b>Use {@link #fuzz(Object, boolean)} if you need control over this.</p>
     *
     * <p>This method will locate suitable properties using the current
     * {@link IPropertyResolver}</p>, use the current {@link IRuleResolver} to figure
     * out which {@link IFuzzingRule} to apply and then assign values according
     * to these rules.</p>
     *
     * @param obj object whose properties should have new values assigned
     * @return object instance (for chaining)
     * @param <T> evidence to avoid cast warnings
     *
     * @see #fuzz(Object, boolean)
     */
    public <T> T fuzz(T obj)
    {
        return fuzz( obj, true );
    }

    /**
     * Apply fuzzing rules to object.
     *
     * <p>This method will locate suitable properties using the current
     * {@link IPropertyResolver}</p>, use the current {@link IRuleResolver} to figure
     * out which {@link IFuzzingRule} to apply and then assign values according
     * to these rules.</p>
     *
     * @param obj object whose properties should have new values assigned
     * @param includingInheritedProperties whether to also assign properties inherited from super classes
     * @return object instance (for chaining)
     * @param <T> evidence to avoid cast warnings
     *
     * @see #fuzz(Object)
     */
    public <T> T fuzz(T obj, boolean includingInheritedProperties)
    {
        Validate.notNull( obj, "obj must not be null" );
        if ( debug ) {
            System.out.println( "Randomizing object " + obj.getClass().getName() );
        }
        final Context info = new Context(this , obj, includingInheritedProperties);
        for ( IProperty property : propertyResolver.getProperties( obj.getClass(), includingInheritedProperties ) )
        {
            if ( debug ) {
                System.out.println( "Assigning random value to "+property);
            }
            info.currentProperty = property;
            getRule( info ).fuzz( info, value -> property.setValue( obj, value  ) );
        }
        return obj;
    }

    private IFuzzingRule getRule(IContext ctx) {
        IFuzzingRule rule = ruleResolver.getRule( ctx );
        if ( rule == null )
        {
            throw new RuntimeException( "Error, found no fuzzing rule for " + ctx.getProperty() );
        }
        return rule;
    }

    /**
     * Sets the rule resolver to use.
     *
     * @param ruleResolver rule resolver
     * @return this instance (for chaining)
     * @see #DEFAULT_RULE_RESOLVER
     */
    public Fuzzer setRuleResolver(IRuleResolver ruleResolver) {
        Validate.notNull( ruleResolver, "ruleResolver must not be null" );
        this.ruleResolver = ruleResolver;
        return this;
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
     * Sets the implementation to be used when resolving properties in need of fuzzing.
     *
     * @param propertyResolver resolver
     * @return this instance (for chaining)
     * @see #DEFAULT_RESOLVER
     * @see #getPropertyResolver()
     * @see CachingPropertyResolver
     */
    public Fuzzer setPropertyResolver(IPropertyResolver propertyResolver)
    {
        Validate.notNull( propertyResolver, "propertyResolver must not be null" );
        this.propertyResolver = propertyResolver;
        return this;
    }

    /**
     * Returns the current {@link IPropertyResolver property resolver}.
     *
     * @return property resolver, never <code>null</code>
     * @see #setPropertyResolver(IPropertyResolver)
     */
    public IPropertyResolver getPropertyResolver()
    {
        return propertyResolver;
    }
}