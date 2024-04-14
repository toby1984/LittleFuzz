
![Build Status](https://github.com/toby1984/LittleFuzz/actions/workflows/maven.yml/badge.svg)

## LittleFuzz

A tiny reflection-based fuzzer written in Java, perfect for unit-testing. Its purpose is to assign random 
values to object properties (out of the box, methods and fields are supported) 
using customizable value generation and property discovery strategies. 

### Requirements (using)

You need to be running at least JDK 17

### Requirements (building)

JDK 17, Maven 3.9.6 or later

To publish to Maven Central, use `mvn -Prelease release:prepare release:perform`.

### Usage

Assuming you're using Maven, just add this to your pom.xml

    <dependency>
      <groupId>de.code-sourcery.littlefuzz</groupId>
      <artifactId>littlefuzz-core</artifactId>
      <version>1.0.4</version>
    </dependency>

First, you'll have to create an instance of the `de.codesourcery.littlefuzz.core.Fuzzer`:

    Fuzzer fuzzer = new Fuzzer();

Then you can register fuzzing rules (`de.codesourcery.littlefuzz.core.IFuzzingRule`) based on a property's 
declaring class and name or based on the property type using the `addPropertyRule()` , `setPropertyRule()`, 
`addTypeRule()` and `setTypeRule()` methods.

The difference between the `addXXX()` and `setXXX()` rules is that the `addXXX()` methods will fail when trying to
to register a rule more than once for any given type/property while the `setXXX()` methods will just overwrite any
rule that may have been been already assigned.

        fuzzer.addPropertyRule( SomeClass.class, "b", (context, setter) -> {} );
        // a rule that just unconditionally increments the properties' value by one
        fuzzer.addTypeRule( (context,setter) -> setter.set( (int) context.getPropertyValue() + 1), Integer.TYPE);

By default, all non-static member fields of a class (except any `this$<number>` references to enclosing classes)
will be fuzzed. You can customize this behaviour by using the `setPropertyResolver(IPropertyResolver)` method.
Property resolution is *not* cached by default so if execution speed is important, wrap the property resolver 
using a `CachingPropertyResolver` like so:

        fuzzer.setFieldResolver( CachingPropertyResolver.wrap( fuzzer.getPropertyResolver() ) );

To decide how to randomize a property value, the following algorithm is used:

1. Check if a fuzzing rule with the property's name and declaring class exists. If it does, use that rule.
2. Check if there's a fuzzing rule matching the property's type. If it does, use that rule. 
3. Throw a `RuntimeException` complaining that no rule for a property could be found.

You can change this algorithm via the `setRuleResolver(IRuleResolver)` method.

Finally, you're ready to fuzz an object:

    fuzzer.fuzz( myObject );
    // fuzzer.fuzz( myObject, false ); // if property resolution should not consider inherited properties

# Extras

Additionally, there's the littlefuzz-extra module includes all of `littlefuzz-core` plus 

- `DifferentValueGenerator`: A wrapper for `IPropertyValueGenerator` instances that makes sure the newly assigned value is never equal to the current property value
- `Randomizer`: Helper functions (like selecting N random values out of a Java `Collection` etc) to generate randomized property values using a `java.util.RandomGenerator`.

To use it, just add this to your pom.xml

    <dependency>
      <groupId>de.code-sourcery.littlefuzz</groupId>
      <artifactId>littlefuzz-extra</artifactId>
      <version>1.0.4</version>
    </dependency>
 